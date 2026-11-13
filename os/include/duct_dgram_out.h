/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_dgram_out.h
 *  @brief Datagram send descriptor and segmented-send group rule, shared by the
 *  worker, engine and syscall layers.
 *
 *  A worker fills the array and, still on its own thread, hands it through
 *  @ref duct_io_dgram_shared_send_batch to the send loop
 *  @ref DUCT_XSEND_GROUPED_DECLARE generates. That loop serves a connected conn's
 *  record spans as well: @ref duct_x_gso_group finds the groups one segmented write
 *  carries, and each platform's @c duct_xport.h supplies the writes and the
 *  plain sends the loop picks between.
 */

#ifndef DUCT_DGRAM_OUT_H
#define DUCT_DGRAM_OUT_H

#include "duct_core.h"
#include "duct_types.h"
#include "duct_wire.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief One outbound datagram: where it goes, and its bytes as two spans.
 *
 *  @c hdr then @c body reach the wire as one datagram, so a payload is sent
 *  from where it already lies. Neither span is owned here; both must outlive
 *  the send.
 */
typedef struct duct_dgram_out {
    duct_peer_t peer; /**< Destination address. */
    duct_view_u8  hdr;  /**< Wire header packed apart from the payload.
                        *  Zero-sized when the header sits at the head of
                        *  @c body. */
    duct_view_u8  body; /**< Payload bytes, or header-plus-payload when @c hdr
                        *  is empty. */
} duct_dgram_out_t;

/** @brief Place of one datagram in a segmented send led by a datagram of
 *  segment size. */
typedef enum duct_x_gso_fit : uint8_t {
    x_gso_fit_none, /**< Outside the group: empty, longer than the segment, or
                      *  bound for another destination. */
    x_gso_fit_full, /**< Segment-sized: the group carries on. */
    x_gso_fit_tail, /**< Shorter: the group's closing segment. */
} duct_x_gso_fit_t;

/** @brief Classify a datagram of @p len bytes against segment size @p seg.
 *  The stack slices one byte stream into @p seg-sized datagrams, so only the
 *  closing one is shorter, and an empty one leaves no bytes to slice. Both
 *  platforms' offload send paths take this rule: Linux @c UDP_SEGMENT, Windows
 *  @c UDP_SEND_MSG_SIZE. */
static inline duct_x_gso_fit_t duct_x_gso_fit(size_t len, size_t seg)
{
    if (!len || len > seg)
        return x_gso_fit_none;
    return len < seg ? x_gso_fit_tail : x_gso_fit_full;
}

/** @brief Segments one segmented write carries, at most, a count every Linux
 *  kernel carrying @c UDP_SEGMENT accepts. */
static constexpr size_t duct_x_gso_segs_max = 64u;

/** @brief Report whether this stack cuts one send into equal-sized datagrams.
 *  Settled once at startup by each platform's @c duct_core.c. */
bool duct_x_has_gso(void);

/** @brief Report whether @p a and @p b name one destination.
 *  Every byte of @c duct_peer_t takes part, port included: two clients behind
 *  one NAT differ in the port alone. An IPv4 peer's unused address tail must
 *  stay zero, as @ref duct_io_peer_from_sockaddr leaves it; a dirty tail reads
 *  as another peer. */
duct_nonnull(1, 2) static inline bool
duct_x_same_peer(const duct_peer_t *a, const duct_peer_t *b)
{
    return memcmp(a, b, sizeof *a) == 0;
}

/** @name Per-entry datagram length a group scanner reads
 *  The whole datagram, header span included.
 *  @{ */
duct_nonnull(1) static inline size_t duct_x_dgram_len_buf(const duct_view_u8 *b)
{
    return b->size;
}

duct_nonnull(1) static inline size_t duct_x_dgram_len_out(const duct_dgram_out_t *m)
{
    return m->hdr.size + m->body.size;
}
/** @} */

/** @name Group scanner generator
 *  Emits @p fn over an array of @p elem_type: @p len_fn answers an entry's
 *  datagram length, and the optional last argument names the member holding
 *  its destination, which must match the lead entry's through
 *  @ref duct_x_same_peer. Every element type carrying a destination passes it;
 *  a connected socket's records all reach its one peer and pass none.
 *  @{
 */
#define DUCT_X_GSO_GROUP_DECLARE(fn, elem_type, len_fn, ...)                  \
    duct_nonnull(1) static inline unsigned fn(const elem_type *m, unsigned n) \
    {                                                                         \
        size_t seg = len_fn(&m[0]);                                           \
        if (!seg)                                                             \
            return 1u;                                                        \
        duct_do_if(seg > duct_udp4_payload_max, return 1u);                   \
        n = (unsigned)duct_min((size_t)n,                                     \
                               duct_min(duct_udp4_payload_max / seg,          \
                                        duct_x_gso_segs_max));                \
        unsigned i = 1u;                                                      \
        for (bool open = true; open && i < n;) {                              \
            bool same = true __VA_OPT__(&&                                    \
                duct_x_same_peer(&m[i].__VA_ARGS__, &m[0].__VA_ARGS__));      \
            auto fit = same ? duct_x_gso_fit(len_fn(&m[i]), seg)              \
                            : x_gso_fit_none;                                 \
            switch (fit) {                                                    \
            case x_gso_fit_full: ++i;               break;                    \
            case x_gso_fit_tail: ++i; open = false; break;                    \
            case x_gso_fit_none:      open = false; break;                    \
            }                                                                 \
        }                                                                     \
        return i;                                                             \
    }
/** @} */

DUCT_X_GSO_GROUP_DECLARE(duct_x_gso_group_bufs, duct_view_u8, duct_x_dgram_len_buf)
DUCT_X_GSO_GROUP_DECLARE(duct_x_gso_group_peers, duct_dgram_out_t,
                         duct_x_dgram_len_out, peer)

/** @brief Count the entries from @p m one segmented write carries.
 *  @p m is a @c duct_view_u8 array of a connected conn's records, or a
 *  @c duct_dgram_out_t array of addressed datagrams, where an entry for another
 *  destination also ends the group. The lead entry's length is the segment size,
 *  @ref duct_x_gso_fit places each later entry, and the group is cut to
 *  @ref duct_x_gso_segs_max and to one datagram payload.
 *  @return 1 or more; exactly 1 for an empty lead entry, or one past a datagram
 *  payload, which the caller sends unsegmented. */
#define duct_x_gso_group(m, n) _Generic((m),                \
        duct_view_u8 *:             duct_x_gso_group_bufs,    \
        const duct_view_u8 *:       duct_x_gso_group_bufs,    \
        duct_dgram_out_t *:       duct_x_gso_group_peers,   \
        const duct_dgram_out_t *: duct_x_gso_group_peers)((m), (n))

/** @brief Send the @p n datagrams at @p m as one segmented write.
 *  @p m holds a connected conn's @c duct_view_u8 records or addressed
 *  @c duct_dgram_out_t datagrams; @p n is a group @ref duct_x_gso_group found.
 *  Each platform supplies @c duct_xsend_gso_bufs and @c duct_xsend_gso_peers.
 *  @return @c rc_ok with all @p n taken; @c rc_again for a code worth
 *  repeating; @c rc_not_supported for every other code, which sends the group
 *  unsegmented. */
#define duct_xsend_gso(fd, m, n) _Generic((m),              \
        duct_view_u8 *:             duct_xsend_gso_bufs,      \
        const duct_view_u8 *:       duct_xsend_gso_bufs,      \
        duct_dgram_out_t *:       duct_xsend_gso_peers,     \
        const duct_dgram_out_t *: duct_xsend_gso_peers)((fd), (m), (n))

/** @brief Send the @p n datagrams at @p m unsegmented.
 *  @p m holds a connected conn's @c duct_view_u8 records or addressed
 *  @c duct_dgram_out_t datagrams. Each platform supplies @c duct_xsend_bufs
 *  and @c duct_xsend_peers.
 *  @param out_sent how many of the first @p n the caller may move past, a
 *         prefix.
 *  @return @c rc_ok with that prefix; for records, also @c rc_again,
 *  @c rc_drop or @c rc_fatal. Addressed datagrams answer @c rc_ok on every
 *  path, so a shared socket never closes over one batch. */
#define duct_xsend_plain(fd, m, n, out_sent) _Generic((m),  \
        duct_view_u8 *:             duct_xsend_bufs,          \
        const duct_view_u8 *:       duct_xsend_bufs,          \
        duct_dgram_out_t *:       duct_xsend_peers,         \
        const duct_dgram_out_t *: duct_xsend_peers)((fd), (m), (n), (out_sent))

/** @brief Segmented writes one send loop made, and the datagrams they carried. */
typedef struct duct_x_gso_tally {
    unsigned writes, /**< Segmented writes the stack took. */
             dgrams; /**< Datagrams those writes carried. */
} duct_x_gso_tally_t;

/** @name Send loop generator
 *  Emits @p fn over an array of @p elem_type. It sends each group
 *  @ref duct_x_gso_group finds as one @ref duct_xsend_gso, and each stretch
 *  between groups through @ref duct_xsend_plain; a group answered
 *  @c rc_not_supported moves the rest of the call onto plain sends.
 *
 *  @c out_sent is the prefix sent. The answer is @c rc_ok, the prefix short of
 *  @c n once a socket fills; @c rc_again or @c rc_fatal as a send answered it;
 *  or @c rc_drop, with nothing sent, for a first datagram too large for the
 *  path. A refused datagram past the first answers @c rc_ok and waits for a
 *  later call to reach it first. Each group a write takes adds one write and its
 *  datagrams to @c tally.
 *  @{
 */
#define DUCT_XSEND_GROUPED_DECLARE(fn, elem_type)                             \
    static duct_result_t                                                      \
    fn(duct_sock_t fd, const elem_type *m, unsigned n, unsigned *out_sent,    \
       duct_x_gso_tally_t *tally, bool *gso_ok)                               \
    {                                                                         \
        *out_sent = 0u;                                                       \
        bool gso = (!gso_ok || *gso_ok) && duct_x_has_gso();                  \
        for (unsigned i = 0u; i < n;) {                                       \
            unsigned end = i,                                                 \
                     group = 1u;                                              \
            for (; end < n; ++end) {                                          \
                group = gso ? duct_x_gso_group(&m[end], n - end) : 1u;        \
                if (group > 1u)                                               \
                    break;                                                    \
            }                                                                 \
            if (end > i) {                                                    \
                unsigned took = 0u;                                           \
                auto rc = duct_xsend_plain(fd, &m[i], end - i, &took);        \
                i += took;                                                    \
                *out_sent = i;                                                \
                switch (rc) {                                                 \
                case rc_ok:                                                   \
                    if (i < end)                                              \
                        return rc_ok;                                         \
                    break;                                                    \
                case rc_drop:                                                 \
                    return i ? rc_ok : rc_drop;                               \
                default:                                                      \
                    return rc;                                                \
                }                                                             \
            }                                                                 \
            if (end == n)                                                     \
                break;                                                        \
            auto rc = duct_xsend_gso(fd, &m[end], group);                     \
            switch (rc) {                                                     \
            case rc_ok:                                                       \
                i = end + group;                                              \
                *out_sent = i;                                                \
                ++tally->writes;                                              \
                tally->dgrams += group;                                       \
                break;                                                        \
            case rc_not_supported:                                            \
                gso = false;                                                  \
                if (gso_ok)                                                   \
                    *gso_ok = false;                                          \
                break;                                                        \
            default:                                                          \
                return rc;                                                    \
            }                                                                 \
        }                                                                     \
        return rc_ok;                                                         \
    }
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* DUCT_DGRAM_OUT_H */
