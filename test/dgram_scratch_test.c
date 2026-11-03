/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file dgram_scratch_test.c
 * @brief A block of a page or more is a duct_new block behind a pointer, never thread-local storage
 *.
 *
 * @ref check_tls_budget reads the PT_TLS segment of this executable, which holds every runtime source
 * compiled into it, and requires it under a page: an array that reaches thread-local storage again
 * costs every thread of the process its size.
 *
 * @ref check_scratch_read drains a datagram listener whose slot pool holds no slot, a pool of 0, so each
 * read lands in the io thread's scratch block: the block is made at the first read and freed with the
 * thread, a classifier is handed the datagram at the block's address, and a scratch that cannot be had
 * reads the datagram into a byte and drops it as truncated, leaving none queued.
 *
 * Includes duct_io.c directly to reach the io module state and its static thread pointer, as
 * shutdown_abandon_test.c does; the io thread is started and joined before the drain runs on the main
 * thread in its place.
 */

#include "../src/duct_io.c"

#include "duct_wfq.h"
#include "test_helpers.h"
#include "dgram_test_helpers.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __linux__
#include <link.h>
#endif

#ifdef __linux__
static size_t g_tls_memsz;

/* The first object dl_iterate_phdr names is the executable itself. */
static int tls_of_executable(struct dl_phdr_info *info, [[maybe_unused]] size_t size,
                             [[maybe_unused]] void *data)
{
    for (unsigned i = 0u; i < info->dlpi_phnum; ++i)
        if (info->dlpi_phdr[i].p_type == PT_TLS)
            g_tls_memsz = info->dlpi_phdr[i].p_memsz;
    return 1;
}

static void check_tls_budget(void)
{
    dl_iterate_phdr(tls_of_executable, nullptr);
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || g_tls_memsz >= (size_t)page) {
        fprintf(stderr, "dgram_scratch: the thread-local segment is %zu bytes, a page is %ld\n",
                g_tls_memsz, page);
        exit(1);
    }
}
#endif

enum { sent_len = 40 };

static unsigned    g_seen;
static const void *g_seen_at;
static size_t      g_seen_len;
static uint8_t     g_seen_bytes[sent_len];

static duct_resolve_disposition_t
capture([[maybe_unused]] void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
        [[maybe_unused]] duct_handle_t *out_tok, [[maybe_unused]] duct_conn_id_t *out_conn_id,
        [[maybe_unused]] void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    ++g_seen;
    g_seen_at = peek.data;
    g_seen_len = peek.size;
    memcpy(g_seen_bytes, peek.data, duct_min(peek.size, sizeof g_seen_bytes));
    return resolve_reject;
}

static duct_proto_t g_proto = { .cfg = { .preparse = capture, .preparse_mode = resolve_sync } };

static void fill(uint8_t *bytes, uint8_t seed)
{
    for (unsigned i = 0u; i < sent_len; ++i)
        bytes[i] = (uint8_t)(seed + i);
}

/* Send one datagram and wait until it is queued on the receiving socket. */
static void send_queued(duct_sock_t tx, duct_sock_t rx, const uint8_t *bytes)
{
    assert(uc_send(tx, bytes, sent_len) == 0);
    struct pollfd pfd = { .fd = rx, .events = POLLIN };
    assert(poll(&pfd, 1, 2000) == 1);
}

static void check_scratch_read(duct_vmq_mpsc_t *wfq)
{
    assert(duct_io_init(1u, wfq, 1u));
    assert(duct_io_start_threads());
    duct_io_request_shutdown();
    duct_io_join();
    auto t = &s_imod.xports[0];

    uint16_t port = 0u;
    auto rx = uc_bind(&port);
    auto tx = uc_connect(port);
    assert(rx != duct_sock_bad && tx != duct_sock_bad);

    duct_x_slot_pool_t pool = {};
    auto protos = duct_at(duct_new(const duct_proto_t *, 1u));
    auto l = duct_new(duct_listener_t);
    assert(protos && l);
    protos[0] = &g_proto;
    l->listen_fd = rx;
    l->xport_type = x_udp;
    l->rx_slots = &pool;
    l->protos = protos;
    l->n_protos = 1u;

    s_io_this = t;
    if (t->dgram_scratch) {
        fprintf(stderr, "dgram_scratch: the block exists before the first read\n");
        exit(1);
    }

    uint8_t sent[sent_len];
    for (uint8_t round = 0u; round < 3u; ++round) {
        fill(sent, (uint8_t)(round * 16u));
        send_queued(tx, rx, sent);
        duct_io_dgram_rx_drain(l);
        if (g_seen != (unsigned)round + 1u || g_seen_len != sizeof sent
            || memcmp(g_seen_bytes, sent, sizeof sent) != 0) {
            fprintf(stderr, "dgram_scratch: round %u: the classifier saw %u datagrams, the last of %zu bytes\n",
                    (unsigned)round, g_seen, g_seen_len);
            exit(1);
        }
        if (!t->dgram_scratch || g_seen_at != duct_at(t->dgram_scratch)
            || duct_len(t->dgram_scratch) != DUCT_LISTENER_DGRAM_DEFAULT) {
            fprintf(stderr, "dgram_scratch: round %u: the datagram did not land in a block of %zu bytes\n",
                    (unsigned)round, (size_t)DUCT_LISTENER_DGRAM_DEFAULT);
            exit(1);
        }
    }
    auto again = duct_io_dgram_rx_scratch();
    if (again.data != duct_at(t->dgram_scratch) || again.size != DUCT_LISTENER_DGRAM_DEFAULT) {
        fprintf(stderr, "dgram_scratch: a second call made another block\n");
        exit(1);
    }

    /* A scratch that cannot be had: the datagram is read into a byte and dropped, and the socket
     * is left empty, not stalled with the datagram still queued. */
    unsigned seen = g_seen;
    s_io_this = nullptr;
    fill(sent, 0x80u);
    send_queued(tx, rx, sent);
    duct_io_dgram_rx_drain(l);
    s_io_this = t;
    if (g_seen != seen || uc_recv_none(rx, 0) != 0) {
        fprintf(stderr, "dgram_scratch: a datagram read with no scratch was classified or left queued\n");
        exit(1);
    }

    duct_listener_destroy(l);
    duct_sock_close(tx);
    s_io_this = nullptr;
    duct_io_cleanup();
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

#ifdef __linux__
    check_tls_budget();
#endif

    auto wfq = duct_wfq_new(1u, 1u, DUCT_WFQ_CAP_HI, DUCT_WFQ_CAP_NORM, DUCT_WFQ_CAP_LO);
    assert(wfq);
    check_scratch_read(wfq);
    duct_vmq_mpsc_del(wfq);

    printf("dgram_scratch: OK (thread-local segment under a page, a read with no slot lands in the io "
           "thread's block, none leaves a datagram queued)\n");
    return 0;
}
