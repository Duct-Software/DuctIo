#include "duct_rio.h"
#include "duct_io.h"
#include "duct_listener.h"
#include "duct_relay.h"
#include "duct_vmq.h"
#include "duct_xport.h"

bool duct_rio_load(SOCKET probe, RIO_EXTENSION_FUNCTION_TABLE *out)
{
    /* Zeroed before the call: a provider reporting success while writing
     * fewer bytes than sizeof(*out) leaves the trailing pointer fields
     * as null, preventing uninitialized memory reads. */
    *out = (RIO_EXTENSION_FUNCTION_TABLE){};
    GUID id = WSAID_MULTIPLE_RIO;
    DWORD bytes = 0;
    int rc = WSAIoctl(probe, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                      &id, sizeof id, out, sizeof *out, &bytes, nullptr, nullptr);
    bool of = rc != 0
           || bytes < sizeof bytes
           || out->cbSize < sizeof *out;
    duct_do_if(of, return false);
    return out->RIORegisterBuffer && out->RIOCreateRequestQueue
        && out->RIOCreateCompletionQueue && out->RIOSendEx
        && out->RIODequeueCompletion && out->RIONotify
        && out->RIOCloseCompletionQueue && out->RIODeregisterBuffer
        && out->RIOResizeCompletionQueue;
}

RIO_EXTENSION_FUNCTION_TABLE *duct_rio_resolve(void)
{
#if DUCT_RIO_FORCE_DISABLE
    /* DUCT_RIO_FORCE_DISABLE build-time override: skips the probe, reports
     * RIO unavailable unconditionally, for deterministic fallback-path.
     */
    return nullptr;
#else
    auto probe = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                            WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO);
    duct_do_if(probe == duct_sock_bad, return nullptr);
    auto table = duct_new(RIO_EXTENSION_FUNCTION_TABLE);
    bool ok = table && duct_rio_load(probe, table);
    closesocket(probe);
    if (!ok)
        duct_del(table);
    return ok ? table : nullptr;
#endif
}

/** @brief One receive descriptor of a ring, the context of its posted receive. */
struct duct_rio_rx_slot {
    duct_rio_rx_t *ring;     /**< The ring this descriptor belongs to. */
    uint32_t       pool_idx; /**< RX pool slot a pooled descriptor reads into, @c treiber_empty for a private cell. */
};

static_assert(alignof(duct_rio_rx_slot_t) > duct_rio_ctx_send_bit,
    "a receive slot's address must leave duct_rio_ctx_send_bit clear");

/** @brief One listener's receive ring: private cells and RX pool slots behind one set of descriptors.
 *  The io thread alone touches it. The first @c first_pooled descriptors read into private cells,
 *  the rest into slots of the listener's RX pool, whose chunks the pool registers.
 */
struct duct_rio_rx {
    RIO_BUFFERID        cells_id, /**< Registration of @c block. */
                        priv_id;  /**< Registration of @c priv, invalid without private cells. */
    RIO_RQ              rq;       /**< Request queue the receives post on, handed over by @c duct_rio_rx_arm. */
    uint8_t            *block,    /**< Address cells and control cells of every descriptor. */
                       *priv;     /**< Data cells of the private descriptors, @c read_bytes each. */
    duct_ptr_t(duct_rio_rx_slot_t) slots; /**< The descriptors. */
    unsigned           *free_stack; /**< Indices of the descriptors with no receive posted. */
    void               *owner;    /**< The backend's listener context, freed with the ring. */
    duct_listener_t    *listener; /**< Listener a datagram is delivered to. */
    duct_x_slot_pool_t *pool;     /**< The listener's RX pool. */
    unsigned            first_pooled, /**< Index of the first pooled descriptor. */
                        read_bytes,   /**< Bytes one receive reads, the listener's datagram span. */
                        free_count;   /**< Descriptors on @c free_stack. */
    bool                closing;  /**< The owner let go: nothing is delivered or re-posted. */
};

/** @brief Pool hook: register a grown chunk as a RIO buffer, its id the cookie.
 *  Answers @c rc_again for a registration the system refuses, which a later take retries.
 */
static duct_result_t s_chunk_up(void *ctx, void *base, size_t bytes, uintptr_t *cookie)
{
    auto rio = (const RIO_EXTENSION_FUNCTION_TABLE *)ctx;
    auto id = rio->RIORegisterBuffer((char *)base, (DWORD)bytes);
    bool ok = duct_rio_buf_ok(id);
    duct_do_if(!ok, return rc_again);
    *cookie = (uintptr_t)id;
    return rc_ok;
}

/** @brief Pool hook: deregister the RIO buffer a retired chunk was registered as. */
static void s_chunk_down(void *ctx, uintptr_t cookie)
{
    auto rio = (const RIO_EXTENSION_FUNCTION_TABLE *)ctx;
    rio->RIODeregisterBuffer((RIO_BUFFERID)cookie);
}

duct_x_slot_hooks_t duct_rio_slot_hooks(const RIO_EXTENSION_FUNCTION_TABLE *rio)
{
    return (duct_x_slot_hooks_t){ .up = s_chunk_up, .down = s_chunk_down, .ctx = (void *)rio };
}

/** @brief RIO span of @p len bytes at @p lead bytes into slot @p idx of @p pool.
 *  The buffer id is the cookie of the slot's chunk, the offset counted from the chunk's base.
 */
static RIO_BUF s_slot_buf(const duct_x_slot_pool_t *pool, uint32_t idx, size_t lead, ULONG len)
{
    return (RIO_BUF){ (RIO_BUFFERID)duct_x_slot_cookie(pool, idx),
                      (ULONG)(duct_x_slot_chunk_off(pool, idx) + lead), len };
}

/** @brief Index of descriptor @p slot in its ring. */
static inline unsigned s_rx_idx(const duct_rio_rx_slot_t *slot)
{
    return (unsigned)(slot - duct_at(slot->ring->slots));
}

/** @brief Address cell of descriptor @p i inside @p ring's registered block. */
static inline struct sockaddr_storage *s_rx_addr(duct_rio_rx_t *ring, unsigned i)
{
    return (struct sockaddr_storage *)(ring->block + (size_t)i * sizeof(struct sockaddr_storage));
}

/** @brief Bytes of one slot's control cell: the header and room for the
 *  segment-size cmsg. Cells sit ahead of the data cells, which keeps them
 *  aligned for @c WSACMSGHDR whatever size a data cell takes. */
static constexpr size_t s_rx_ctl_cell = RIO_CMSG_BASE_SIZE + sizeof(duct_x_cmsg_dword_t);

/** @brief Control cell @p i inside @p ring's registered block. */
static inline RIO_CMSG_BUFFER *s_rx_ctl(duct_rio_rx_t *ring, unsigned i)
{
    return (RIO_CMSG_BUFFER *)(ring->block + (size_t)duct_len(ring->slots) * sizeof(struct sockaddr_storage)
                               + (size_t)i * s_rx_ctl_cell);
}

/** @brief Segment size slot @p i's read reported, 0 for one that coalesced
 *  nothing. @c TotalLength is clamped to the cell, so a long answer never walks
 *  into the data cell. */
static inline size_t s_rx_seg(duct_rio_rx_t *ring, unsigned i)
{
    auto ctl = s_rx_ctl(ring, i);
    size_t len = duct_min((size_t)ctl->TotalLength, s_rx_ctl_cell);
    if (len < RIO_CMSG_BASE_SIZE)
        return 0u;
    return duct_x_gro_seg((WSABUF){ (ULONG)(len - RIO_CMSG_BASE_SIZE),
                                    (char *)ctl + RIO_CMSG_BASE_SIZE });
}

unsigned duct_rio_rx_depth(const duct_rio_rx_t *ring)
{
    return (unsigned)duct_len(ring->slots);
}

void duct_rio_rx_arm(duct_rio_rx_t *ring, RIO_RQ rq)
{
    ring->rq = rq;
}

/** @brief Deregister the block and the private cells of @p ring, those that registered. */
static void s_rx_unregister(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring)
{
    if (duct_rio_buf_ok(ring->cells_id))
        rio->RIODeregisterBuffer(ring->cells_id);
    if (duct_rio_buf_ok(ring->priv_id))
        rio->RIODeregisterBuffer(ring->priv_id);
}

/** @brief Return the pool slots of the @p pooled descriptors from @p slots on to @p pool. */
static void s_rx_unpool(duct_x_slot_pool_t *pool, const duct_rio_rx_slot_t *slots, unsigned pooled)
{
    for (unsigned i = 0u; i < pooled; ++i)
        duct_x_slot_release(pool, slots[i].pool_idx);
}

duct_rio_rx_t *duct_rio_rx_create(const RIO_EXTENSION_FUNCTION_TABLE *rio,
                                  void *owner, duct_listener_t *listener)
{
    auto pool = listener->rx_slots;
    unsigned span = (unsigned)duct_listener_dgram_span(listener);
    unsigned want = duct_rio_rx_ring_slots(duct_dgram_sock_rcvbuf, span);
    size_t blk_bytes = (size_t)want * (sizeof(struct sockaddr_storage) + s_rx_ctl_cell);
    duct_auto_del auto ring = duct_new(duct_rio_rx_t);
    duct_auto_del auto slots = duct_new(duct_rio_rx_slot_t, want);
    duct_auto_del auto free_stack = duct_at(duct_new(unsigned, want));
    duct_auto_del auto block = duct_at(duct_new(uint8_t, blk_bytes));
    duct_do_if(!ring || !slots || !free_stack || !block, return nullptr);
    /* The pooled descriptors take the high indices: the refill pops the free stack from its top,
     * so they post first. A pool that cannot register chunks, or lends fewer slots than asked,
     * leaves the low descriptors on private cells, and at most half the pool goes to the ring. */
    bool shared = pool->range.base && pool->hooks.up;
    unsigned pooled = 0u,
             room = shared ? duct_min(want, (unsigned)duct_len(pool->slots) / 2u) : 0u;
    for (; pooled < room; ++pooled) {
        uint32_t idx = duct_x_slot_acquire(pool);
        duct_do_if(idx == treiber_empty, break);
        duct_at(slots)[want - 1u - pooled].pool_idx = idx;
    }
    unsigned first = want - pooled;
    size_t priv_bytes = (size_t)first * span;
    duct_auto_del auto priv = duct_at(duct_new(uint8_t, priv_bytes));
    duct_do_if(first && !priv, s_rx_unpool(pool, duct_at(slots) + first, pooled); return nullptr);
    ring->cells_id = rio->RIORegisterBuffer((char *)block, (DWORD)blk_bytes);
    if (priv)
        ring->priv_id = rio->RIORegisterBuffer((char *)priv, (DWORD)priv_bytes);
    bool registered = duct_rio_buf_ok(ring->cells_id) && (!priv || duct_rio_buf_ok(ring->priv_id));
    duct_do_if(!registered,
        s_rx_unregister(rio, ring);
        s_rx_unpool(pool, duct_at(slots) + first, pooled);
        return nullptr
    );
    for (unsigned i = 0u; i < want; ++i) {
        duct_at(slots)[i].ring = ring;
        if (i < first)
            duct_at(slots)[i].pool_idx = treiber_empty;
        free_stack[i] = i;
    }
    ring->owner = owner;
    ring->listener = listener;
    ring->pool = pool;
    ring->first_pooled = first;
    ring->read_bytes = span;
    ring->free_count = want;
    ring->slots = duct_move(slots);
    ring->free_stack = duct_move(free_stack);
    ring->block = duct_move(block);
    ring->priv = duct_move(priv);
    return duct_move(ring);
}

void duct_rio_rx_destroy(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring)
{
    s_rx_unregister(rio, ring);
    s_rx_unpool(ring->pool, duct_at(ring->slots) + ring->first_pooled,
                (unsigned)duct_len(ring->slots) - ring->first_pooled);
    duct_del(ring->priv);
    duct_del(ring->block);
    duct_del(ring->slots);
    duct_del(ring->free_stack);
    duct_del(ring);
}

/** @brief Post one RIOReceiveEx for @p ring's slot @p i.
 *  The slot's control cell restarts at @c TotalLength 0, so a completion that
 *  carries no cmsg reads as uncoalesced. */
static bool s_rx_post(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring, unsigned i)
{
    auto desc = &duct_at(ring->slots)[i];
    RIO_BUF addr_buf = { ring->cells_id,
        (ULONG)((char *)s_rx_addr(ring, i) - (char *)ring->block),
        sizeof(struct sockaddr_storage) };
    auto ctl = s_rx_ctl(ring, i);
    ctl->TotalLength = 0u;
    RIO_BUF ctl_buf = { ring->cells_id,
        (ULONG)((char *)ctl - (char *)ring->block),
        (ULONG)s_rx_ctl_cell };
    RIO_BUF data_buf = i >= ring->first_pooled
        ? s_slot_buf(ring->pool, desc->pool_idx, ring->pool->lead, ring->read_bytes)
        : (RIO_BUF){ ring->priv_id, (ULONG)((size_t)i * ring->read_bytes), ring->read_bytes };
    return rio->RIOReceiveEx(ring->rq, &data_buf, 1u, nullptr, &addr_buf,
        &ctl_buf, nullptr, 0u, desc);
}

/** @brief Post from @p ring's free stack until it empties or the OS refuses.
 *  The pop happens only on a true RIOReceiveEx, so a refused post leaves its
 *  slot where it was and the next refill retries it.
 *  @return slots still unposted. */
static unsigned s_rx_refill(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring)
{
    while (ring->free_count) {
        bool posted = s_rx_post(rio, ring, ring->free_stack[ring->free_count - 1u]);
        duct_do_if(!posted, break);
        --ring->free_count;
    }
    return ring->free_count;
}

bool duct_rio_rx_prime(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring)
{
    return s_rx_refill(rio, ring) < duct_len(ring->slots);
}

bool duct_rio_rx_close(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_rx_t *ring)
{
    ring->closing = true;
    if (ring->free_count != duct_len(ring->slots))
        return false;
    void *owner = ring->owner;
    duct_rio_rx_destroy(rio, ring);
    duct_del(owner);
    return true;
}

void duct_rio_rx_dispatch(const RIO_EXTENSION_FUNCTION_TABLE *rio,
                          duct_rio_rx_slot_t *slot, LONG status, ULONG bytes)
{
    auto ring = slot->ring;
    unsigned i = s_rx_idx(slot);
    if (!ring->closing)
        switch (status) {
        case 0: {
            auto peer = duct_io_peer_from_sockaddr((const struct sockaddr *)s_rx_addr(ring, i));
            if (i < ring->first_pooled) {
                duct_io_on_dgram(ring->listener, &peer,
                                 &(duct_view_u8){ ring->priv + (size_t)i * ring->read_bytes, bytes },
                                 (uint32_t)s_rx_seg(ring, i));
                break;
            }
            uint32_t next = duct_x_slot_acquire(ring->pool);
            bool lent = duct_io_on_dgram_slot(ring->listener, &peer, slot->pool_idx, bytes,
                                              (uint32_t)s_rx_seg(ring, i), next != treiber_empty);
            if (lent)
                slot->pool_idx = next;
            else if (next != treiber_empty)
                duct_x_slot_release(ring->pool, next);
            break;
        }
        default:
            duct_dbg_errf("RIO status %ld", (long)status);
            break;
        }
    ring->free_stack[ring->free_count++] = i;
    if (ring->closing) {
        duct_discard duct_rio_rx_close(rio, ring);
        return;
    }
    duct_discard s_rx_refill(rio, ring);
}

typedef struct duct_rio_tx duct_rio_tx_t;

/** @brief One send in flight, the context of its posted request. */
struct duct_rio_tx_op {
    duct_rio_tx_t *tx;  /**< The send state the descriptor belongs to. */
    uint32_t       ref; /**< Reference of the TX slot the send reads from. */
};

static_assert(alignof(duct_rio_tx_op_t) > duct_rio_ctx_send_bit,
    "a send's context must leave duct_rio_ctx_send_bit free to tag");

/** @brief One listener's RIO send state, stored in its @c dgram_tx_rio.
 *  The io thread alone touches it. The slots a send reads from belong to the listener's TX pools,
 *  which the state frees with itself.
 */
struct duct_rio_tx {
    RIO_RQ              rq;        /**< Request queue the sends post on. */
    duct_listener_t    *listener;  /**< Listener whose outbox a completion drains again, read while @c closing is false. */
    duct_x_slot_pool_t *pools;     /**< The listener's pair of TX slot pools. */
    duct_ptr_t(duct_rio_tx_op_t) ops; /**< One descriptor per send in flight, @c duct_rio_tx_depth of them. */
    unsigned           *free_stack, /**< Indices of the free descriptors. */
                        free_count, /**< Descriptors on @c free_stack. */
                        inflight;   /**< Sends posted and not yet settled. */
    bool                closing;   /**< The listener let go: the last settled send frees the state. */
};

/** @brief Argument of the send callback of one drain: the table and the state. */
typedef struct {
    const RIO_EXTENSION_FUNCTION_TABLE *rio;
    duct_rio_tx_t                      *tx;
} tx_post_t;

/** @brief Free the send state with its TX slot pools and descriptors. */
static void s_tx_release(duct_rio_tx_t *tx)
{
    duct_listener_tx_slots_free(tx->pools);
    duct_del(tx->ops);
    duct_del(tx->free_stack);
    duct_del(tx);
}

bool duct_rio_tx_create(RIO_RQ rq, duct_listener_t *listener)
{
    auto pools = listener->tx_slots;
    duct_do_if(!pools, return false);
    duct_auto_del auto tx = duct_new(duct_rio_tx_t);
    duct_auto_del auto ops = duct_new(duct_rio_tx_op_t, duct_rio_tx_depth);
    duct_auto_del auto free_stack = duct_at(duct_new(unsigned, duct_rio_tx_depth));
    duct_do_if(!tx || !ops || !free_stack, return false);
    duct_do_if(pools[0].lead < sizeof(struct sockaddr_storage), return false);
    duct_do_if(!pools[0].hooks.up || !pools[1].hooks.up, return false);
    for (unsigned i = 0u; i < duct_rio_tx_depth; ++i)
        free_stack[i] = i;
    tx->rq = rq;
    tx->listener = listener;
    tx->pools = pools;
    tx->free_count = duct_rio_tx_depth;
    tx->ops = duct_move(ops);
    tx->free_stack = duct_move(free_stack);
    listener->dgram_tx_rio = duct_move(tx);
    return true;
}

void duct_rio_tx_free(duct_listener_t *listener)
{
    auto tx = (duct_rio_tx_t *)listener->dgram_tx_rio;
    listener->dgram_tx_rio = nullptr;
    listener->tx_slots = nullptr;
    tx->closing = true;
    if (!tx->inflight)
        s_tx_release(tx);
}

/** @brief Post the slot of one queued entry as a RIOSendEx.
 *  The send callback of @ref duct_io_dgram_send_drain. Writes the peer address into the slot's
 *  lead and sends the payload from the slot's registered chunk. A post the system refuses returns
 *  the slot at once, and the entry is spent either way.
 *  @return false when no descriptor is free, which leaves the entry queued.
 */
static bool s_tx_post(void *arg, const duct_dgram_tx_entry_t *entry)
{
    auto post = (tx_post_t *)arg;
    auto tx = post->tx;
    duct_do_if(!tx->free_count, return false);
    uint32_t ref = entry->slot,
             idx = ref & ~duct_x_slot_ref_large;
    auto pool = duct_x_slot_ref_pool(tx->pools, ref);
    duct_discard duct_io_sockaddr_from_peer(&entry->peer,
                                            (struct sockaddr_storage *)duct_x_slot_data(pool, idx));
    RIO_BUF data_buf = s_slot_buf(pool, idx, pool->lead, entry->len);
    RIO_BUF addr_buf = s_slot_buf(pool, idx, 0u, sizeof(struct sockaddr_storage));
    auto op = &duct_at(tx->ops)[tx->free_stack[tx->free_count - 1u]];
    *op = (duct_rio_tx_op_t){ .tx = tx, .ref = ref };
    BOOL rc = post->rio->RIOSendEx(tx->rq, &data_buf, 1u, nullptr, &addr_buf,
        nullptr, nullptr, 0u, duct_rio_ctx_send(op));
    if (rc) {
        --tx->free_count;
        ++tx->inflight;
    } else
        duct_x_slot_put(tx->pools, ref);
    return true;
}

void duct_rio_tx_drain(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_listener_t *listener)
{
    tx_post_t post = { .rio = rio, .tx = (duct_rio_tx_t *)listener->dgram_tx_rio };
    duct_io_dgram_send_drain(listener, s_tx_post, &post);
}

/** @brief Settle a completed send: return its descriptor and its slot.
 *  The last settled send of a closing state frees it; a live state drains its listener's outbox
 *  again when @p redrain, so a backlog deeper than the send depth refills as each send completes.
 */
static void s_tx_settle(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_tx_op_t *op, bool redrain)
{
    auto tx = op->tx;
    tx->free_stack[tx->free_count++] = (unsigned)(op - duct_at(tx->ops));
    duct_x_slot_put(tx->pools, op->ref);
    if (--tx->inflight == 0u && tx->closing)
        s_tx_release(tx);
    else if (redrain && !tx->closing)
        duct_rio_tx_drain(rio, tx->listener);
}

void duct_rio_tx_complete(const RIO_EXTENSION_FUNCTION_TABLE *rio, duct_rio_tx_op_t *op)
{
    s_tx_settle(rio, op, true);
}

/* Both loops below batch, and a completion they hand on can free the ring or
 * pool it belongs to. That stays safe because a slot is returned when its
 * completion is processed, never when it is dequeued: a later entry of the
 * same batch for that same ring or pool means a slot is still out, so the
 * free cannot have happened ahead of it. Returning a slot at dequeue time
 * turns either batch into a use-after-free. RIODequeueCompletion signals
 * failure as RIO_CORRUPT_CQ, ULONG_MAX, in the count itself, so each loop
 * bounds that count by the array's own size before indexing with it. */
void duct_rio_cq_drain(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq)
{
    RIORESULT results[duct_rio_cq_batch];
    ULONG n;
    while ((n = rio->RIODequeueCompletion(cq, results, duct_rio_cq_batch)) > 0u
           && n <= duct_rio_cq_batch)
        for (ULONG i = 0u; i < n; ++i) {
            auto ctx = results[i].RequestContext;
            if (duct_rio_ctx_is_send(ctx)) {
                duct_rio_tx_complete(rio, (duct_rio_tx_op_t *)duct_rio_ctx_slot(ctx));
                continue;
            }
            duct_rio_rx_dispatch(rio, (duct_rio_rx_slot_t *)duct_rio_ctx_slot(ctx),
                                 results[i].Status, results[i].BytesTransferred);
        }
    rio->RIONotify(cq);
}

void duct_rio_cq_flush(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq)
{
    RIORESULT results[duct_rio_cq_batch];
    ULONG n;
    while ((n = rio->RIODequeueCompletion(cq, results, duct_rio_cq_batch)) > 0u
           && n <= duct_rio_cq_batch)
        for (ULONG i = 0u; i < n; ++i) {
            auto ctx = results[i].RequestContext;
            if (duct_rio_ctx_is_send(ctx)) {
                s_tx_settle(rio, (duct_rio_tx_op_t *)duct_rio_ctx_slot(ctx), false);
                continue;
            }
            duct_rio_rx_dispatch(rio, (duct_rio_rx_slot_t *)duct_rio_ctx_slot(ctx),
                                 results[i].Status, results[i].BytesTransferred);
        }
    rio->RIONotify(cq);
}

RIO_CQ duct_rio_cq_create(const RIO_EXTENSION_FUNCTION_TABLE *rio,
                          PRIO_NOTIFICATION_COMPLETION notify,
                          DWORD *cq_depth, DWORD *cq_used)
{
    RIO_CQ cq = rio->RIOCreateCompletionQueue(duct_rio_cq_depth, notify);
    if (cq) {
        rio->RIONotify(cq);
        *cq_depth = duct_rio_cq_depth;
        *cq_used = 0u;
    }
    return cq;
}

void duct_rio_cq_close(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq)
{
    rio->RIOCloseCompletionQueue(cq);
}

bool duct_rio_cq_ensure(const RIO_EXTENSION_FUNCTION_TABLE *rio, RIO_CQ cq,
                        DWORD *cq_depth, DWORD *cq_used, DWORD need)
{
    DWORD required = *cq_used + need;
    if (required > *cq_depth) {
        BOOL ok = rio->RIOResizeCompletionQueue(cq, required);
        duct_do_if(!ok, return false);
        *cq_depth = required;
    }
    *cq_used = required;
    return true;
}
