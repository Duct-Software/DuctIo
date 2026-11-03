/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file noise_tunnel_test.c
 * @brief Noise tunnel over the real engine, W-3 shape: `x_udp_shared` +
 * `receiver_index` demux via `preparse`, so a peer's address can change
 * mid-session (roaming) without losing the session — verified below by
 * literally closing and reopening the client's socket on a new port
 * mid-test and continuing the same encrypted session.
 *
 * Builds on W-2-lite (`x_udp_peer`, no demux, no roaming — superseded by
 * this file). Demultiplexing needs one thing `duct_noise.c` deliberately
 * doesn't provide (see its own @file doc): a crypto-blind way for the
 * io-thread to tell "new handshake attempt" from "transport data for an
 * already-established session" apart *before* any decryption. That is the
 * one-byte @c vpn_type_handshake / @c vpn_type_transport prefix below, plus
 * a 4-byte @c receiver_index on transport-data packets — deliberately not
 * WireGuard's own two-index wire format: this listener only ever demuxes
 * *incoming* (client-to-server) traffic, so one server-assigned index is
 * enough. A 16-byte @c mac1 trailer on handshake-type frames only (W-4,
 * see the "mac1 anti-DoS pre-check" section below) is the one piece of
 * WireGuard's own anti-DoS wire format this file does carry — mac2/cookie-
 * reply (the under-load, round-trip tier, defending against a
 * spoofed-source-address flood from a sender who already knows the
 * server's public key) is deliberately not implemented: WireGuard's own
 * construction encrypts the cookie reply with XChaCha20Poly1305, which
 * OpenSSL has no native EVP cipher for (WireGuard's own userspace
 * implementations hand-roll it from HChaCha20 + ChaCha20Poly1305) — real,
 * non-trivial crypto work that deserves its own dedicated pass rather than
 * a rushed one here.
 *
 * The `receiver_index -> session token` table is real cross-thread state
 * (populated on whichever worker owns the session, read on the listener's
 * io thread inside `preparse`) but deliberately not a bespoke concurrent
 * hash table: `resolve_sync`'s own contract is "O(1), lock-free,
 * non-blocking" (`duct_protocol.h`), so the table is a fixed-size array of
 * atomic session tokens, index = the wire's own receiver_index — the same
 * generation-checked-handle idiom `duct_conn_handle_t`/`duct_session_handle_t`
 * already use everywhere in this engine, not a new one. Slot allocation
 * reuses `duct_treiber.h`'s existing lock-free free-list macro, the same
 * one the engine's own conn/session pools are built on.
 */

#include "duct.h"
#include "duct_noise_internal.h"
#include "duct_session.h"
#include "duct_treiber.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdatomic.h>

#include "test_helpers.h"
#include "dgram_test_helpers.h"

#ifndef _WIN32
#include <netinet/in.h>
#endif

/* Engine built-in, not declared in the public duct_wire.h — same forward
 * declaration dgram_test.c's own copy uses. */
duct_wire_t *duct_wire_create_dgram_batch(size_t max_dgram, bool framed);

static uint16_t th_port = 0u;

static const uint8_t s_push_marker[] = { 'S', 'R', 'V', '-', 'P', 'U', 'S', 'H' };

/** @brief Send @c s_push_marker on the session's current reply path. */
static duct_result_t
s_server_push([[maybe_unused]] duct_session_t *session, duct_response_t *out,
              [[maybe_unused]] void *ctx)
{
    duct_response_same(out,
                       (duct_view_u8){ (void *)s_push_marker, sizeof s_push_marker },
                       fl_send_copy, fl_frame_none);
    return rc_ok;
}

/* ── Wire-level type + receiver_index framing — demux only, orthogonal to
 * duct_noise.c's own message bytes (see @file). Big-endian on the wire,
 * matching every other multi-byte field this codebase frames by hand. ── */
static constexpr uint8_t  vpn_type_handshake = 1u;
static constexpr uint8_t  vpn_type_transport = 4u;
static constexpr size_t   vpn_index_size = 4u;

static void vpn_put_index(uint8_t out[4], uint32_t idx)
{
    out[0] = (uint8_t)(idx >> 24); out[1] = (uint8_t)(idx >> 16);
    out[2] = (uint8_t)(idx >> 8);  out[3] = (uint8_t)idx;
}

static uint32_t vpn_get_index(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
         | ((uint32_t)in[2] << 8)  | (uint32_t)in[3];
}

/* ── MTU/PMTU (W-4) — the one genuinely actionable piece today ────────
 * WireGuard's own reference tunnel MTU: 1500 (typical Ethernet) minus
 * IPv4/UDP/WG-header overhead. Reference value only — nothing in this file
 * enforces a payload-size cap against it: there is no encapsulated-IP-
 * packet forwarding layer in this transport yet to make that meaningful
 * (TUN attachment is future work, see the plan file's own "Прикладной
 * слой" section), and real Path MTU *feedback* (reading an ICMP
 * Fragmentation-Needed reply via IP_RECVERR/MSG_ERRQUEUE on Linux, an
 * entirely different mechanism on Windows) needs a consumer for that
 * feedback that does not exist yet either — both deferred until that
 * layer does. */
static constexpr size_t vpn_tunnel_mtu = 1420u;

/** @brief Set the DF (Don't Fragment) bit on the listener's own outgoing
 *  UDP socket, so packets this transport sends rely on real Path MTU
 *  discovery (an oversized one is dropped upstream with an ICMP
 *  Fragmentation-Needed reply, not silently reassembled at the IP layer)
 *  instead of masking a too-large tunnel MTU. Platform socket-option work,
 *  orthogonal to the engine's own frame abstraction — best-effort, a
 *  failure here does not fail the listener bind. */
static void vpn_set_df(duct_sock_t fd)
{
#ifdef _WIN32
    DWORD val = 1;
    setsockopt(fd, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&val, sizeof val);
#elif defined(__APPLE__)
    int val = 1;
    setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof val);
#else
    int val = IP_PMTUDISC_DO;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof val);
#endif
}

/* ── mac1 anti-DoS pre-check (W-4) — see @file for scope. ──────────────
 * A keyed MAC over a handshake-type frame's own bytes (type prefix +
 * Noise message 1), appended as a fixed 16-byte trailer, keyed by
 * Hash(Label-Mac1 || server_static_pub) — WireGuard's own construction:
 * anyone who knows the server's PUBLIC key (already required for this
 * protocol's IK pattern, out of band, same as always) can compute a valid
 * mac1 without any shared secret, so this is not authentication — it only
 * filters traffic from a sender who does not even know which server they
 * are addressing (a blind/misdirected flood) before any expensive work:
 * checked in vpn_preparse (io-thread, resolve_sync), before a session,
 * index slot, or duct_noise_hs_t is ever allocated for it.
 *
 * The MAC itself is native *keyed* BLAKE2s — RFC 7693's own keyed mode,
 * 16-byte output, fetched as the "BLAKE2SMAC" EVP_MAC provider (OpenSSL
 * 3.x) — matching WireGuard's own construction exactly, not HMAC-BLAKE2s:
 * those are two different constructions with different outputs for the
 * same key and data, despite both starting from the same hash primitive
 * (HMAC-BLAKE2s is what this transport's own Noise HKDF legitimately uses
 * internally, a different, correctly-HMAC context — do not copy that call
 * shape here by analogy). The key-derivation hash one line below (unkeyed
 * BLAKE2s-256 over the label + pubkey) is unaffected by this distinction —
 * only the per-frame MAC itself needs the native keyed mode. */
static constexpr size_t vpn_mac1_size = 16u;
static const uint8_t vpn_mac1_label[] = "mac1----"; /* WireGuard's own 8-byte label */

/** @brief Derive the mac1 key from the server's static public key — the
 *  server computes this once at startup; a client computes the identical
 *  value from the same (already-known) server public key. */
static void vpn_mac1_derive_key(uint8_t out[32], const uint8_t server_pub[32])
{
    uint8_t buf[sizeof vpn_mac1_label - 1u + 32u];
    memcpy(buf, vpn_mac1_label, sizeof vpn_mac1_label - 1u);
    memcpy(buf + sizeof vpn_mac1_label - 1u, server_pub, 32u);
    unsigned outlen = 0u;
    EVP_Digest(buf, sizeof buf, out, &outlen, EVP_blake2s256(), nullptr);
}

/** @brief Compute the 16-byte mac1 trailer over @p data (the frame's own
 *  bytes up to, not including, the trailer itself) — native keyed BLAKE2s
 *  (RFC 7693's own keyed mode, 16-byte output), not HMAC-BLAKE2s: those are
 *  two different constructions with different outputs for the same
 *  key/data, and WireGuard's own mac1 is the former. Zeroed up front so a
 *  fetch/init failure (should never happen for a built-in provider
 *  algorithm) fails the comparison at the call site rather than matching
 *  against leftover stack garbage. */
static void vpn_mac1_compute(const uint8_t key[32], const uint8_t *data, size_t len,
                             uint8_t out[16])
{
    memset(out, 0, vpn_mac1_size);
    auto mac = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    duct_do_if(!mac, return);
    auto ctx = EVP_MAC_CTX_new(mac);
    if (ctx) {
        size_t size = vpn_mac1_size;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size),
            OSSL_PARAM_construct_end(),
        };
        size_t outlen = 0u;
        if (EVP_MAC_init(ctx, key, 32u, params))
            duct_discard EVP_MAC_update(ctx, data, len);
        duct_discard EVP_MAC_final(ctx, out, &outlen, vpn_mac1_size);
        EVP_MAC_CTX_free(ctx);
    }
    EVP_MAC_free(mac);
}

/* ── receiver_index -> session token: fixed-size atomic array + Treiber
 * free-list, per this file's own @file doc. ── */
static constexpr unsigned vpn_index_slots_max = 1024u;

typedef struct {
    uint32_t      _Atomic next;    /* DUCT_TREIBER_DECLARE free-list link */
    duct_handle_t _Atomic session; /* 0 = free; live session token while assigned */
} vpn_index_slot_t;

DUCT_TREIBER_DECLARE(s_vpn_idx, vpn_index_slot_t, next)

typedef struct {
    _Atomic uint64_t free_head;
    vpn_index_slot_t slots[vpn_index_slots_max];
} vpn_index_table_t;

static void vpn_index_table_init(vpn_index_table_t *t)
{
    s_vpn_idx_seed(&t->free_head, t->slots, vpn_index_slots_max);
}

/** @brief Worker-side: claim a slot for @p tok. @return the slot's index
 *  (the wire's own receiver_index), or @ref vpn_index_slots_max if none free. */
static uint32_t vpn_index_alloc(vpn_index_table_t *t, duct_handle_t tok)
{
    uint32_t idx = s_vpn_idx_pop(&t->free_head, t->slots);
    if (idx == treiber_empty)
        return vpn_index_slots_max;
    duct_atomic_store(&t->slots[idx].session, tok, release);
    return idx;
}

/** @brief Worker-side: release @p idx back to the free list. */
static void vpn_index_free(vpn_index_table_t *t, uint32_t idx)
{
    duct_atomic_store(&t->slots[idx].session, 0u, relaxed);
    s_vpn_idx_push(&t->free_head, t->slots, idx);
}

/** @brief io-thread side (@ref vpn_preparse only): O(1), lock-free —
 *  @ref resolve_sync's own contract. A stale or reused index still resolves
 *  to *some* token here; @c duct_session_by_handle's own generation check
 *  (already run by the engine's resolve_join handling, not repeated here)
 *  is what actually rejects a token whose session has since closed — this
 *  function does not duplicate that check. */
static duct_handle_t vpn_index_lookup(const vpn_index_table_t *t, uint32_t idx)
{
    return idx < vpn_index_slots_max
         ? duct_atomic_load(&t->slots[idx].session, acquire) : 0u;
}

/* ── Server-side protocol: Noise responder state lives in proto_state ──── */

typedef struct {
    const duct_noise_keypair_t *server_kp;
    const uint8_t              *psk; /* 32 bytes */
    vpn_index_table_t          *idx_table;
    uint8_t                     mac1_key[32]; /* vpn_mac1_derive_key(server_kp->pub) */
    uint64_t                    reject_after_ms; /* WireGuard's own
                                 * Reject-After-Time, 180 s there; a session
                                 * with no successful (re-)handshake within
                                 * this long of its last one is force-closed,
                                 * see vpn_on_reject_timer. */
} vpn_proto_ctx_t;

/** @brief Handshake state and transport state are never both live *for the
 *  original handshake*: exactly one of the union members is valid, selected
 *  by @c established. A re-handshake attempt arriving after @c established
 *  (WireGuard does not distinguish "peer lost our message 2, retrying" from
 *  "peer is proactively rekeying" — both are just a fresh message 1) is a
 *  genuinely simultaneous third state — the old transport must keep serving
 *  traffic while a new handshake is processed — so it cannot share the
 *  union's storage and lives in its own field instead, non-null only while
 *  such an attempt is in flight. @c server_kp/@c psk are cached from
 *  @c vpn_proto_ctx_t at create time so a fresh @c duct_noise_hs_t can be
 *  built on demand from @ref vpn_handle_handshake alone: @c on_frame does
 *  not receive @c ctx (see @c duct_frame_fn), only @c proto_state. */
typedef struct {
    bool           established;
    uint32_t       recv_index; /* this session's own slot in idx_table, valid
                                 * for the session's whole life (assigned at
                                 * create_state, released at destroy_state) —
                                 * not just while established, since a peer
                                 * may re-send message 1 (e.g. after losing
                                 * our message 2, or to rekey) at any time. */
    const duct_noise_keypair_t *server_kp;
    const uint8_t              *psk;
    uint64_t                    reject_after_ms; /* cached from vpn_proto_ctx_t,
                                 * same reason as server_kp/psk above. */
    duct_timer_id_t              reject_timer_id; /* 0 = none armed yet; armed/
                                 * rearmed on every successful (re-)handshake
                                 * in vpn_handle_handshake, fires
                                 * vpn_on_reject_timer if no further
                                 * (re-)handshake lands within reject_after_ms. */
    duct_noise_hs_t            *rehandshake_hs; /* non-null only while a
                                 * post-established re-handshake attempt is
                                 * in flight; never touches vst->transport
                                 * until that attempt fully succeeds. */
    union {
        duct_noise_hs_t        *hs;        /* valid while !established */
        duct_noise_transport_t  transport; /* valid once established */
    };
} vpn_session_state_t;

static duct_result_t
vpn_create_state(duct_session_t *s, void *ctx, void **out)
{
    auto pctx = (const vpn_proto_ctx_t *)ctx;
    auto vst = duct_new(vpn_session_state_t);
    duct_do_if(!vst, return rc_no_memory);

    auto stok = duct_session_handle_from_live(s);
    vst->recv_index = vpn_index_alloc(pctx->idx_table, *(const duct_handle_t *)&stok);
    if (vst->recv_index == vpn_index_slots_max) {
        duct_del(vst);
        return rc_no_memory;
    }
    vst->server_kp = pctx->server_kp;
    vst->psk = pctx->psk;
    vst->reject_after_ms = pctx->reject_after_ms;
    vst->hs = duct_noise_hs_create(pctx->server_kp, nullptr, pctx->psk, false);
    if (!vst->hs) {
        vpn_index_free(pctx->idx_table, vst->recv_index);
        duct_del(vst);
        return rc_no_memory;
    }
    *out = vst;
    return rc_ok;
}

static void
vpn_destroy_state([[maybe_unused]] duct_session_t *s, void *ctx, void *state)
{
    auto pctx = (const vpn_proto_ctx_t *)ctx;
    auto vst = (vpn_session_state_t *)state;
    duct_noise_hs_destroy(vst->rehandshake_hs);
    if (vst->established)
        duct_noise_transport_destroy(&vst->transport);
    else
        duct_noise_hs_destroy(vst->hs);
    vpn_index_free(pctx->idx_table, vst->recv_index);
    duct_del(vst);
}

/**
 * @brief io-thread, @ref resolve_sync: tell a fresh handshake attempt from
 * an existing session's transport data apart, crypto-blind, before any conn
 * or session exists for the former — exactly @ref duct_preparse_fn's own
 * purpose. A recognized @c receiver_index resolves straight to the owning
 * session; the engine's own existing @c fl_proto_dgram_shared migration
 * handling (not this function's concern) takes it from there, aliasing the
 * peer's current address whether or not it matches what that session last
 * saw — this is the whole roaming mechanism, already built, not something
 * this file adds to.
 */
static duct_resolve_disposition_t
vpn_preparse(void *ctx, [[maybe_unused]] const duct_peer_t *peer, duct_view_u8 peek,
            duct_handle_t *out_tok, duct_conn_id_t *out_conn_id,
            [[maybe_unused]] void **out_user_ctx, [[maybe_unused]] size_t *out_lead)
{
    auto pctx = (const vpn_proto_ctx_t *)ctx;
    auto p = (const uint8_t *)peek.data;
    if (peek.size < 1u)
        return resolve_not_me;
    if (p[0] == vpn_type_handshake) {
        /* mac1 anti-DoS pre-check (W-4, see @file) — before any session,
         * index slot, or duct_noise_hs_t is allocated for this frame. */
        duct_do_if(peek.size < 1u + vpn_mac1_size, return resolve_not_me);
        uint8_t expect[vpn_mac1_size];
        vpn_mac1_compute(pctx->mac1_key, p, peek.size - vpn_mac1_size, expect);
        duct_do_if(memcmp(expect, p + peek.size - vpn_mac1_size, vpn_mac1_size) != 0,
                  return resolve_not_me);
        return resolve_new;
    }
    if (p[0] != vpn_type_transport || peek.size < 1u + vpn_index_size)
        return resolve_not_me;

    auto tok = vpn_index_lookup(pctx->idx_table, vpn_get_index(p + 1u));
    duct_do_if(!tok, return resolve_not_me);
    *out_tok = tok;
    *out_conn_id = duct_conn_id_primary;
    return resolve_join;
}

/**
 * @brief Hand @p len heap bytes at @p buf to the framework as the response.
 *
 * The only safe response shape a callback in this file can produce: both
 * the handshake reply and the transport echo are only known-final after a
 * seal/write call fills a fresh buffer, and that buffer must remain valid
 * past this callback's own return — @c fl_send_copy's own contract stages
 * the payload only *after* @c on_frame returns, by which point a stack
 * buffer local to this call (or one it calls) is no longer live storage.
 * @c fl_send_owned exists for exactly this: with no @c release set the
 * framework frees @p buf with @c duct_del once staging completes, whatever
 * the callback's own stack looked like by then.
 */
static void vpn_respond_owned(duct_response_t *out, void *buf, size_t len)
{
    *out = (duct_response_t){
        .payload = { buf, len },
        .flags = fl_send_owned,
        .conn_id = duct_conn_id_same,
        .stream_id = duct_stream_id_same,
        .control.stream_op_conn_id = duct_conn_id_same,
    };
}

/**
 * @brief Run one Noise message-1 -> message-2 exchange on @p hs — shared
 * core for both the original handshake and any later re-handshake attempt
 * on an already-established session (WireGuard itself does not distinguish
 * "peer lost our message 2, retrying" from "peer is proactively rekeying":
 * both are just a fresh message 1, authenticated the same way either case).
 * Destroys @p hs unconditionally before returning, success or failure: a
 * Noise handshake object's chaining state is irreversibly mutated by any
 * step that runs, including a failing one, so it can never be safely
 * reused for a later attempt — the caller must always start any retry from
 * a freshly created object, never this one again. Does not touch @p vst at
 * all beyond reading @c recv_index; the caller alone decides what a success
 * or failure means for session state. */
static bool
vpn_run_handshake(duct_noise_hs_t *hs, duct_view_u8 msg1, uint32_t recv_index,
                  duct_noise_transport_t *out_transport, duct_response_t *out)
{
    /* remote_static/payload: required output params, deliberately unused
     * past this call — no allowlist/replay policy in this minimal pass (see
     * @file); a real integrator checks remote_static here before trusting
     * the peer at all. */
    uint8_t remote_static[32],
            payload[64];
    size_t payload_len = 0u;
    if (!duct_noise_hs_read_msg1(hs, msg1, remote_static, payload, sizeof payload, &payload_len)) {
        duct_noise_hs_destroy(hs);
        return false;
    }

    auto resp = duct_at(duct_new(uint8_t, vpn_index_size + duct_noise_msg2_size));
    if (!resp) {
        duct_noise_hs_destroy(hs);
        return false;
    }
    vpn_put_index(resp, recv_index);
    size_t msg2_len = 0u;
    if (!duct_noise_hs_write_msg2(hs, (duct_view_u8){}, resp + vpn_index_size, duct_noise_msg2_size, &msg2_len)) {
        duct_del(resp);
        duct_noise_hs_destroy(hs);
        return false;
    }

    bool split_ok = duct_noise_hs_split(hs, out_transport);
    duct_noise_hs_destroy(hs);
    if (!split_ok) {
        duct_del(resp);
        return false;
    }
    vpn_respond_owned(out, resp, vpn_index_size + msg2_len);
    return true;
}

/** @brief (Re-)arm this session's Reject-After-Time backstop on @p out —
 *  called after every successful (re-)handshake, initial or rekey alike, so
 *  a session with no further (re-)handshake within @c reject_after_ms of
 *  its last one is force-closed by @ref vpn_on_reject_timer, matching
 *  WireGuard's own Reject-After-Time. @c cancel_id targets whatever timer
 *  @c reject_timer_id already held (0 on the very first handshake — the
 *  worker's own cancel step is a no-op for a zero id) before @c id_out
 *  overwrites it with the new one — both actions apply from the same
 *  response, no ordering hazard (see duct_worker.c's own timer-apply order:
 *  start always runs before cancel). Payload/flags on @p out are untouched:
 *  this only adds a control side effect to whatever @ref vpn_run_handshake
 *  already staged as the response. */
static void vpn_arm_reject_timer(vpn_session_state_t *vst, duct_response_t *out)
{
    out->control.timer.cancel_id = vst->reject_timer_id;
    out->control.timer.delay_ms = vst->reject_after_ms;
    out->control.timer.id_out = &vst->reject_timer_id;
}

/** @brief One handshake-type frame: the initial handshake while
 *  @c !established (@c vst->hs, recreated fresh on any failure so a later
 *  retry never reuses a partially-mutated object), or a re-handshake while
 *  already @c established (@c vst->rehandshake_hs — a genuinely simultaneous
 *  third state, see @ref vpn_session_state_t's own doc for why it cannot
 *  share the union). The re-handshake path never touches @c vst->transport
 *  until @ref vpn_run_handshake fully succeeds, so in-flight traffic under
 *  the old key keeps working even if this attempt fails partway; a stale,
 *  still-in-flight previous re-handshake attempt is discarded rather than
 *  reused for the same reason @c vst->hs is never reused after a failure. */
static duct_result_t
vpn_handle_handshake(vpn_session_state_t *vst, const duct_frame_t *frame, duct_response_t *out)
{
    /* Strip this file's own 1-byte type prefix and 16-byte mac1 trailer —
     * vpn_preparse already verified the latter; the actual Noise message 1
     * bytes are what remains between them. */
    duct_do_if(frame->payload.size < 1u + vpn_mac1_size, return rc_drop);
    duct_view_u8 msg1 = { (uint8_t *)frame->payload.data + 1u,
                        frame->payload.size - 1u - vpn_mac1_size };

    if (!vst->established) {
        duct_do_if(!vst->hs, return rc_drop);
        duct_noise_transport_t t = {};
        if (vpn_run_handshake(vst->hs, msg1, vst->recv_index, &t, out)) {
            vst->transport = t;
            vst->established = true;
            vpn_arm_reject_timer(vst, out);
            return rc_ok;
        }
        vst->hs = duct_noise_hs_create(vst->server_kp, nullptr, vst->psk, false);
        return rc_drop;
    }

    if (vst->rehandshake_hs)
        duct_noise_hs_destroy(vst->rehandshake_hs);
    vst->rehandshake_hs = duct_noise_hs_create(vst->server_kp, nullptr, vst->psk, false);
    duct_do_if(!vst->rehandshake_hs, return rc_drop);

    duct_noise_transport_t t = {};
    bool ok = vpn_run_handshake(vst->rehandshake_hs, msg1, vst->recv_index, &t, out);
    vst->rehandshake_hs = nullptr; /* vpn_run_handshake already destroyed it, success or not */
    duct_do_if(!ok, return rc_drop);

    duct_noise_transport_destroy(&vst->transport);
    vst->transport = t;
    vpn_arm_reject_timer(vst, out);
    return rc_ok;
}

/** @brief Established: past this file's own type+index prefix (already
 *  used by @ref vpn_preparse to route here, ignored from this point on —
 *  the session itself is the routing), unseal the "useful load", seal the
 *  same bytes back with no prefix at all: this listener never demuxes its
 *  own replies, only the client's requests. */
static duct_result_t
vpn_handle_transport(vpn_session_state_t *vst, const duct_frame_t *frame, duct_response_t *out)
{
    duct_do_if(frame->payload.size < 1u + vpn_index_size, return rc_drop);
    duct_view_u8 sealed_in = { (uint8_t *)frame->payload.data + 1u + vpn_index_size,
                             frame->payload.size - 1u - vpn_index_size };

    uint8_t plain[512];
    size_t plain_len = 0u;
    duct_do_if(!duct_noise_transport_unseal(&vst->transport, sealed_in,
                                            plain, sizeof plain, &plain_len),
              return rc_drop);

    size_t sealed_cap = duct_noise_transport_seal_size(plain_len);
    auto sealed = duct_at(duct_new(uint8_t, sealed_cap));
    duct_do_if(!sealed, return rc_drop);
    size_t sealed_len = duct_noise_transport_seal(&vst->transport,
                                                  &(duct_view_u8){ plain, plain_len }, 1u,
                                                  sealed, sealed_cap);
    if (!sealed_len) {
        duct_del(sealed);
        return rc_drop;
    }

    vpn_respond_owned(out, sealed, sealed_len);
    return rc_ok;
}

/** @brief Reject-After-Time fire: no (re-)handshake landed within
 *  @c reject_after_ms of the last one — close, matching WireGuard's own
 *  hard backstop under @ref duct_noise_seal_counter_max's message-count
 *  one. Ordinary transport traffic never rearms this timer (only
 *  @ref vpn_arm_reject_timer does, from a successful handshake) — an
 *  otherwise-idle-of-handshakes but data-active session still expires here,
 *  same as real WireGuard. */
static duct_result_t
vpn_on_reject_timer([[maybe_unused]] duct_session_t *s, duct_response_t *out,
                    [[maybe_unused]] void *proto_state, [[maybe_unused]] uint64_t arg)
{
    duct_response_close_session(out, close_timeout);
    return rc_ok;
}

/** @brief Dispatch on the wire-level type byte, not on @c established: a
 *  handshake-type frame must reach @ref vpn_handle_handshake regardless of
 *  session state (that function alone decides initial-vs-re-handshake) —
 *  dispatching on @c established instead would misroute a message-1 retry
 *  or rekey attempt arriving after the session is already established
 *  straight into the transport path, where it would just be dropped as
 *  garbage and the peer would be stuck until session timeout. */
static duct_result_t
vpn_on_dgram([[maybe_unused]] duct_session_t *s, [[maybe_unused]] duct_conn_id_t conn_id,
            const duct_frame_t *frame, duct_response_t *out, void *proto_state)
{
    auto vst = (vpn_session_state_t *)proto_state;
    duct_do_if(frame->payload.size < 1u, return rc_drop);
    auto type = ((const uint8_t *)frame->payload.data)[0];
    if (type == vpn_type_handshake)
        return vpn_handle_handshake(vst, frame, out);
    if (type == vpn_type_transport)
        return vst->established ? vpn_handle_transport(vst, frame, out) : rc_drop;
    return rc_drop;
}

/* ── Client side: raw Noise initiator over a UDP socket it fully owns —
 * demuxes nothing itself, just remembers the server-assigned recv_index and
 * prefixes it on every transport-data send. ── */

static const char *
s_client_handshake(duct_sock_t fd, duct_noise_hs_t *hs_i, const uint8_t mac1_key[32], uint32_t *out_recv_index)
{
    static const char hello[] = "client-hello";
    uint8_t msg1[256];
    msg1[0] = vpn_type_handshake;
    size_t msg1_len = 0u;
    duct_do_if(!duct_noise_hs_write_msg1(hs_i, (duct_view_u8){ (void *)hello, sizeof(hello) - 1u },
                                         msg1 + 1u, sizeof(msg1) - 1u, &msg1_len),
              return "write_msg1 failed");
    vpn_mac1_compute(mac1_key, msg1, 1u + msg1_len, msg1 + 1u + msg1_len);
    duct_do_if(uc_send(fd, msg1, 1u + msg1_len + vpn_mac1_size) != 0, return "send msg1 failed");

    uint8_t rbuf[256];
    ssize_t got = uc_recv(fd, (char *)rbuf, sizeof rbuf);
    duct_do_if(got < 0, return "recv msg2 failed");
    duct_do_if((size_t)got < vpn_index_size, return "msg2 too short");
    *out_recv_index = vpn_get_index(rbuf);
    duct_do_if(!duct_noise_hs_read_msg2(hs_i, (duct_view_u8){ rbuf + vpn_index_size, (size_t)got - vpn_index_size }),
              return "read_msg2 failed (mutual auth)");
    return nullptr;
}

/** @brief One "useful load" round trip on @p t (its send/recv keys and
 *  counters are independent halves of the same struct — one transport, not
 *  two): seal, prefix with type+recv_index, send, receive the (unprefixed)
 *  echo, unseal, verify it matches. Client-only helper — @c uc_send/
 *  @c uc_recv are synchronous syscalls, so (unlike the server's @c on_frame)
 *  there is no deferred-staging lifetime concern here; plain stack buffers
 *  are fine. */
static const char *
s_client_round(duct_sock_t fd, duct_noise_transport_t *t, uint32_t recv_index,
              const char *plain, size_t plain_len)
{
    uint8_t out[1u + vpn_index_size + 64u];
    out[0] = vpn_type_transport;
    vpn_put_index(out + 1u, recv_index);
    size_t sealed_len = duct_noise_transport_seal(t, &(duct_view_u8){ (void *)plain, plain_len }, 1u,
                                                  out + 1u + vpn_index_size, 64u);
    duct_do_if(!sealed_len, return "seal failed");
    duct_do_if(uc_send(fd, out, 1u + vpn_index_size + sealed_len) != 0, return "send failed");

    uint8_t rbuf[64];
    ssize_t got = uc_recv(fd, (char *)rbuf, sizeof rbuf);
    duct_do_if(got < 0, return "recv failed");

    uint8_t opened[32];
    size_t opened_len = 0u;
    duct_do_if(!duct_noise_transport_unseal(t, (duct_view_u8){ rbuf, (size_t)got },
                                            opened, sizeof opened, &opened_len),
              return "unseal failed");
    duct_do_if(opened_len != plain_len || memcmp(opened, plain, opened_len) != 0,
              return "echoed payload mismatch");

    printf("noise_tunnel: useful load round-trip OK: '%.*s'\n", (int)opened_len, opened);
    return nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IOLBF, 0);

    duct_engine_t *io = nullptr;
    duct_wire_t *wire = nullptr;
    duct_proto_t *proto = nullptr;
    duct_noise_hs_t *hs_i = nullptr;
    duct_sock_t fd = duct_sock_bad,
                spoof_fd = duct_sock_bad;
    duct_handle_t victim_tok = 0;
    bool thread_started = false;
    pthread_t th;
    const char *err = nullptr;
    duct_sock_t listen_fd = duct_sock_bad;

    duct_noise_keypair_t kp_server = {}, kp_client = {};
    uint8_t psk[32] = {};
    uint8_t mac1_key[32] = {}; /* vpn_mac1_derive_key(kp_server.pub) — computed
                                 * independently by client and server alike in
                                 * a real deployment, from the server's public
                                 * key alone; one local suffices in this
                                 * single-process test. */
    duct_noise_transport_t t_client = {}, t_client_rekeyed = {};
    vpn_index_table_t idx_table = {};
    vpn_proto_ctx_t pctx = {};
    uint32_t recv_index = 0u, recv_index_rekeyed = 0u;

    if (!duct_noise_keypair_generate(&kp_server) || !duct_noise_keypair_generate(&kp_client)) {
        err = "keypair generation failed";
        goto cleanup;
    }
    RAND_bytes(psk, sizeof psk);
    vpn_mac1_derive_key(mac1_key, kp_server.pub);
    vpn_index_table_init(&idx_table);

    io = duct_engine_launch(&(duct_engine_cfg_t){ .io_threads = 1, .workers = 1 });
    if (!io) { err = "io create failed"; goto cleanup; }

    wire = duct_wire_create_dgram_batch(0u, false);
    if (!wire) { err = "wire create failed"; goto cleanup; }
    /* Reject-After-Time is short relative to WireGuard's 180 s, but leaves
     * ample room for the spoof check's 200 ms wait and CI scheduling before
     * the test explicitly waits for expiration below. */
    pctx = (vpn_proto_ctx_t){ .server_kp = &kp_server, .psk = psk, .idx_table = &idx_table,
                              .reject_after_ms = 1500u };
    memcpy(pctx.mac1_key, mac1_key, sizeof mac1_key);
    proto = duct_proto_create(&(duct_proto_cfg_t){
        .name = "noise-tunnel", .wire = wire,
        .on_frame = vpn_on_dgram,
        .on_timer = vpn_on_reject_timer,
        .create_state_ctx = &pctx,
        .create_state = vpn_create_state,
        .destroy_state = vpn_destroy_state,
        .preparse = vpn_preparse,
        .preparse_mode = resolve_sync,
        .preparse_ctx = &pctx,
        .max_response = 2048u,
        .flags = fl_proto_dgram_shared,
    });
    if (proto)
        proto->owned_wire = wire;
    else
        duct_wire_destroy(wire);
    if (!proto) { err = "proto create failed"; goto cleanup; }

    if (duct_listener_bind(io, &(duct_listener_cfg_t){ .kind = listener_dgram,
            .addr = "127.0.0.1", .n_protos = 1, .protos = (const duct_proto_t *[]){ proto },
        }, &th_port, &listen_fd, 1u, nullptr) != rc_ok) {
        err = "listener bind failed";
        goto cleanup;
    }
    vpn_set_df(listen_fd);
    if (pthread_create(&th, nullptr, th_run, io) != 0) { err = "thread create failed"; goto cleanup; }
    thread_started = true;

    fd = uc_connect(th_port);
    if (fd == duct_sock_bad) { err = "client connect failed"; goto cleanup; }

    /* mac1 rejection: a handshake-type frame with a wrong mac1 gets no
     * reply at all — vpn_preparse rejects it before any session or index
     * slot is ever allocated (the actual DoS-mitigation property, verified
     * end to end rather than just by inspection). A minimal, undersized
     * frame is enough: preparse only checks type + trailer length before
     * computing mac1 over whatever precedes it. */
    {
        duct_sock_t probe_fd = uc_connect(th_port);
        if (probe_fd == duct_sock_bad) { err = "mac1 probe connect failed"; goto cleanup; }
        uint8_t bad[1u + vpn_mac1_size] = { vpn_type_handshake };
        bool sent_ok = uc_send(probe_fd, bad, sizeof bad) == 0;
        int no_reply = sent_ok ? uc_recv_none(probe_fd, 300) : -1;
        close(probe_fd);
        if (!sent_ok) { err = "mac1 probe send failed"; goto cleanup; }
        if (no_reply != 0) { err = "server replied to a bad-mac1 handshake frame"; goto cleanup; }
        printf("noise_tunnel: bad mac1 correctly rejected with no reply\n");
    }

    hs_i = duct_noise_hs_create(&kp_client, kp_server.pub, psk, true);
    if (!hs_i) { err = "handshake state create failed"; goto cleanup; }

    err = s_client_handshake(fd, hs_i, mac1_key, &recv_index);
    if (err) goto cleanup;
    printf("noise_tunnel: handshake established over the real engine (recv_index=%u)\n", recv_index);

    if (!duct_noise_hs_split(hs_i, &t_client)) { err = "client split failed"; goto cleanup; }
    duct_noise_hs_destroy(hs_i);
    hs_i = nullptr;

    for (unsigned round = 0u; round < 4u; ++round) {
        char plain[32];
        int plen = snprintf(plain, sizeof plain, "payload-%u", round);
        err = s_client_round(fd, &t_client, recv_index, plain, (size_t)plen);
        if (err) goto cleanup;
    }

    /* Roaming: close this socket, open a fresh one on a new ephemeral local
     * port (simulating a NAT rebind / network change), and keep using the
     * same encrypted session — proves demux by recv_index, not by source
     * address, actually works end to end, not just in principle. */
    close(fd);
    fd = uc_connect(th_port);
    if (fd == duct_sock_bad) { err = "roamed client reconnect failed"; goto cleanup; }
    err = s_client_round(fd, &t_client, recv_index, "payload-roamed", 14u);
    if (err) goto cleanup;
    printf("noise_tunnel: roamed to a new local port, session continued\n");

    /* Re-handshake on the same, already-established session: a fresh
     * message 1 arriving after established must not be misrouted into the
     * transport path and silently dropped (see vpn_on_dgram's own doc) — the
     * same wire type byte that started the original handshake must work
     * again here, this time producing a fresh message 2 and swapping in
     * fresh transport keys, in place, on the same session/recv_index. */
    hs_i = duct_noise_hs_create(&kp_client, kp_server.pub, psk, true);
    if (!hs_i) { err = "re-handshake state create failed"; goto cleanup; }
    err = s_client_handshake(fd, hs_i, mac1_key, &recv_index_rekeyed);
    if (err) goto cleanup;
    if (recv_index_rekeyed != recv_index) { err = "re-handshake changed recv_index unexpectedly"; goto cleanup; }
    if (!duct_noise_hs_split(hs_i, &t_client_rekeyed)) { err = "re-handshake client split failed"; goto cleanup; }
    duct_noise_hs_destroy(hs_i);
    hs_i = nullptr;
    err = s_client_round(fd, &t_client_rekeyed, recv_index, "payload-rekeyed", 15u);
    if (err) goto cleanup;
    printf("noise_tunnel: re-handshake after established succeeded, fresh keys work\n");

    /* Authenticated migration: a datagram carrying this session's own
     * recv_index from a foreign address, whose body fails AEAD, must not move
     * the reply path. Client-driven traffic cannot show that — every
     * legitimate round re-adopts the peer before its own reply lands — so the
     * check rides a server-initiated send, which is also what a real tunnel
     * does with inbound traffic. */
    spoof_fd = uc_connect(th_port);
    if (spoof_fd == duct_sock_bad) { err = "spoof socket create failed"; goto cleanup; }
    {
        uint8_t junk[1u + vpn_index_size + 64u];
        junk[0] = vpn_type_transport;
        vpn_put_index(junk + 1u, recv_index);
        memset(junk + 1u + vpn_index_size, 0xA5,
               sizeof junk - 1u - vpn_index_size);
        if (uc_send(spoof_fd, junk, sizeof junk) != 0) {
            err = "spoof datagram send failed";
            goto cleanup;
        }
    }
    th_sleep_ms(200u);
    victim_tok = vpn_index_lookup(pctx.idx_table, recv_index);
    if (!victim_tok) { err = "session token lookup failed"; goto cleanup; }
    if (duct_session_invoke_sync(io, victim_tok, s_server_push, nullptr) != rc_ok) {
        err = "server push invoke failed";
        goto cleanup;
    }
    if (uc_recv_none(spoof_fd, 300) != 0) {
        err = "server push went to the spoofed address";
        goto cleanup;
    }
    {
        uint8_t pbuf[128];
        ssize_t pgot = uc_recv(fd, (char *)pbuf, sizeof pbuf);
        if (pgot != (ssize_t)sizeof s_push_marker
            || memcmp(pbuf, s_push_marker, sizeof s_push_marker) != 0) {
            err = "server push did not reach the authenticated peer";
            goto cleanup;
        }
    }
    printf("noise_tunnel: spoofed index did not move the reply path\n");

    /* Reject-After-Time enforcement: no further (re-)handshake lands within
     * reject_after_ms of the one above — the server-side timer alone closes
     * the session, no client action involved. A client message sent after
     * that gets no reply at all: the session (and its recv_index slot) is
     * gone, not just slow to answer. */
    th_sleep_ms((unsigned)(pctx.reject_after_ms * 2u));
    {
        uint8_t probe[1u + vpn_index_size + 64u];
        probe[0] = vpn_type_transport;
        vpn_put_index(probe + 1u, recv_index);
        static const char msg[] = "probe";
        size_t sealed_len = duct_noise_transport_seal(&t_client_rekeyed,
            &(duct_view_u8){ (void *)msg, sizeof(msg) - 1u }, 1u, probe + 1u + vpn_index_size, 64u);
        if (!sealed_len) { err = "post-reject-timeout probe seal failed"; goto cleanup; }
        if (uc_send(fd, probe, 1u + vpn_index_size + sealed_len) != 0) {
            err = "post-reject-timeout probe send failed";
            goto cleanup;
        }
    }
    if (uc_recv_none(fd, 500) != 0) {
        err = "session still answered after Reject-After-Time elapsed";
        goto cleanup;
    }
    printf("noise_tunnel: session closed on Reject-After-Time with no rekey, as expected\n");

cleanup:
    duct_noise_transport_destroy(&t_client);
    duct_noise_transport_destroy(&t_client_rekeyed);
    duct_noise_hs_destroy(hs_i);
    if (fd != duct_sock_bad) close(fd);
    if (spoof_fd != duct_sock_bad) close(spoof_fd);
    if (thread_started) {
        duct_engine_stop(io);
        pthread_join(th, nullptr);
    }
    duct_engine_destroy(io);
    duct_proto_destroy(proto);

    if (err) {
        fprintf(stderr, "noise_tunnel: %s\n", err);
        return 1;
    }
    printf("noise_tunnel: OK (Noise handshake + encrypted useful load + roaming, all over the real engine)\n");
    return 0;
}
