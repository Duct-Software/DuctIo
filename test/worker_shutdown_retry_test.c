/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file worker_shutdown_retry_test.c
 *  @brief A response parked for retry releases its payload exactly once, even
 *  when shutdown arrives before it ever commits.
 *
 *  The device refuses every reservation, so each response the protocol
 *  produces parks and none is ever written; the run then stops the engine and
 *  counts. Payloads are @c fl_send_owned with the author's own release, which
 *  is the shape a parked node carries whole — the copying branch of
 *  @c s_retry_frame_save fires only for a payload that owns nothing.
 *
 *  Two paths can do the releasing: the retry drain, once the conn it targets
 *  is gone, and @c s_retry_clear at worker shutdown. A graceful stop reaches
 *  the first, so this run does not isolate the second — it guards the
 *  invariant both serve, and passes with either one alone.
 */

#include "duct.h"
#include "test_helpers.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/eventfd.h>
#include <unistd.h>
#endif
#include <stdatomic.h>

static constexpr unsigned wait_ms   = 15000u;
static constexpr unsigned pkt_bytes = 128u;
static constexpr unsigned pkt_total = 8u;

static atomic_int g_attach_rc = -1;
static atomic_int g_responses = 0;
static atomic_int g_released  = 0;
static atomic_int g_committed = 0;

static unsigned g_left = pkt_total;
static uint8_t g_pkt[pkt_total][pkt_bytes];
static unsigned g_seq = 0u;

#ifdef _WIN32
typedef HANDLE device_signal_t;
static device_signal_t s_signal_open(void)
{
    return CreateEventW(nullptr, FALSE, FALSE, nullptr);
}
static bool s_signal_raise(device_signal_t d) { return SetEvent(d) != 0; }
static void s_signal_close(device_signal_t d) { CloseHandle(d); }
#else
typedef int device_signal_t;
static device_signal_t s_signal_open(void)
{
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    return fd < 0 ? 0 : fd;
}
static bool s_signal_raise(device_signal_t d)
{
    uint64_t one = 1u;
    return write(d, &one, sizeof one) == (ssize_t)sizeof one;
}
static void s_signal_close(device_signal_t d) { close(d); }
#endif

static device_signal_t g_device_event = 0;

static duct_result_t device_read([[maybe_unused]] void *ctx, duct_view_u8 *out,
                                 unsigned max, unsigned *n)
{
    unsigned produced = 0u;
    while (produced < max && g_left > 0u) {
        memcpy(g_pkt[g_seq], &g_seq, sizeof g_seq);
        out[produced] = duct_view(duct_view_u8, g_pkt[g_seq], pkt_bytes);
        ++produced;
        ++g_seq;
        --g_left;
    }
    *n = produced;
    return produced ? rc_ok : rc_again;
}

static void *device_write_reserve([[maybe_unused]] void *ctx,
                                  [[maybe_unused]] size_t size)
{
    return nullptr;
}

static duct_result_t device_write_commit([[maybe_unused]] void *ctx,
                                         [[maybe_unused]] void *buf,
                                         [[maybe_unused]] size_t len)
{
    duct_discard duct_atomic_fetch(add, &g_committed, 1, release);
    return rc_ok;
}

static void device_release([[maybe_unused]] void *ctx) {}

static void payload_release(void *arg)
{
    free(arg);
    duct_discard duct_atomic_fetch(add, &g_released, 1, release);
}

static duct_result_t
on_session_open([[maybe_unused]] duct_session_t *s,
                [[maybe_unused]] duct_handle_t tok,
                [[maybe_unused]] void *user_ctx,
                [[maybe_unused]] duct_response_t *out,
                [[maybe_unused]] void *proto_state)
{
    g_device_event = s_signal_open();
    if (!g_device_event) {
        duct_atomic_store(&g_attach_rc, (int)rc_no_memory, release);
        return rc_ok;
    }
    duct_device_ops_t ops = {
        .wait_handle = (void *)(intptr_t)g_device_event,
        .read = device_read,
        .write_reserve = device_write_reserve,
        .write_commit = device_write_commit,
        .release = device_release,
        .ctx = (void *)(intptr_t)g_device_event,
    };
    auto rc = duct_conn_attach_device(s, 1u, &ops);
    duct_atomic_store(&g_attach_rc, (int)rc, release);
    if (rc != rc_ok) {
        s_signal_close(g_device_event);
        g_device_event = 0;
    }
    return rc_ok;
}

static duct_result_t
on_frame([[maybe_unused]] duct_session_t *s, duct_conn_id_t conn_id,
         const duct_frame_t *frame, duct_response_t *out,
         [[maybe_unused]] void *proto_state)
{
    if (conn_id != 1u)
        return rc_ok;
    auto owned = malloc(frame->payload.size);
    if (!owned)
        return rc_ok;
    memcpy(owned, frame->payload.data, frame->payload.size);
    out->payload = duct_view(duct_view_u8, owned, frame->payload.size);
    out->flags = fl_send_owned;
    out->release = payload_release;
    out->release_arg = owned;
    duct_discard duct_atomic_fetch(add, &g_responses, 1, release);
    return rc_ok;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);
    auto io = duct_engine_launch(&(duct_engine_cfg_t){
        .io_threads = 1, .workers = 1,
    });
    if (!io) {
        fprintf(stderr, "worker_shutdown_retry: io create failed\n");
        return 1;
    }
    auto wire = duct_wire_create_length_prefix(0u);
    auto proto = wire ? duct_proto_create(&(duct_proto_cfg_t){
        .name = "worker_shutdown_retry", .wire = wire, .on_frame = on_frame,
        .on_session_open = on_session_open,
    }) : nullptr;
    if (proto)
        proto->owned_wire = wire;
    else if (wire)
        duct_wire_destroy(wire);
    if (!proto) {
        fprintf(stderr, "worker_shutdown_retry: proto create failed\n");
        duct_engine_destroy(io);
        return 1;
    }
    uint16_t port = 0u;
    if (duct_io_listen(io, "127.0.0.1", &port, proto) != rc_ok) {
        fprintf(stderr, "worker_shutdown_retry: listen failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, th_run, io) != 0) {
        fprintf(stderr, "worker_shutdown_retry: thread create failed\n");
        duct_engine_destroy(io);
        duct_proto_destroy(proto);
        return 1;
    }
    auto primary = th_connect(port);
    const char *error = nullptr;
    if (primary == duct_sock_bad)
        error = "primary connect failed";
    else if (!th_wait_int(&g_attach_rc, (int)rc_ok, wait_ms))
        error = "duct_conn_attach_device did not return rc_ok";
    if (!error && !s_signal_raise(g_device_event))
        error = "device signal failed";
    if (!error && !th_wait_int(&g_responses, (int)pkt_total, wait_ms))
        error = "the protocol never produced its responses";

    if (primary != duct_sock_bad)
        close(primary);
    duct_engine_stop(io);
    pthread_join(thread, nullptr);
    duct_engine_destroy(io);

    int responses = duct_atomic_load(&g_responses, acquire),
        released  = duct_atomic_load(&g_released, acquire);
    if (!error && duct_atomic_load(&g_committed, acquire) != 0)
        error = "a reservation succeeded: nothing was left parked to clear";
    if (!error && released != responses)
        error = "a response parked at shutdown never released its payload";
    if (!error && released == 0)
        error = "nothing parked: the run proved nothing";

    duct_proto_destroy(proto);
    if (g_device_event)
        s_signal_close(g_device_event);

    if (error) {
        fprintf(stderr, "worker_shutdown_retry: %s (responses=%d, released=%d, "
                        "committed=%d)\n",
                error, responses, released,
                duct_atomic_load(&g_committed, acquire));
        return 1;
    }
    printf("worker_shutdown_retry: OK (%d responses parked, all released at "
           "shutdown)\n", released);
    return 0;
}
