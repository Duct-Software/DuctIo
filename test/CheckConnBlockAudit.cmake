# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Duct Software

# Source audit of the `conn_block_audit` test. Run as
#   cmake -DSRCDIR=<ductio/src> -P CheckConnBlockAudit.cmake
# It fails when a conn-path source names an allocation or a struct member the
# conn-block milestone removed: a per-conn vm mapping or standalone OLB/queue
# constructor in duct_conn.c (everything a conn owns is carved out of its block,
# the one duct_new left is the pool struct itself), the dead CL1 members
# rx_buf/tx_buf/inter_lane/ctx anywhere a conn is touched, and the retired
# heap wire-parser/codec API anywhere (per-conn parse and codec state is carved
# out of the conn block's wire slots).
#
# B8-full, the zero invariant over duct_worker.c's conn paths: every TX
# backpressure class that dies with its conn (frame, fin, engine, close,
# dgram_tx) parks in the conn block's own TX retry region behind the
# DUCT_CONN_RETRY_TX_NODES quota, its variable-width copies in the region's
# copy slots (DUCT_CONN_RETRY_TX_COPIES / _COPY_MAX), its RX slot pin on the
# parked node itself. The heap allocations a conn path may still name are,
# each pinned by an exact count below:
#   - retry_emit and retry_timer nodes: stream- and session-owned; both carve
#     in the session block's own retry regions behind the
#     DUCT_SESSION_RETRY_EMIT_NODES / _TIMER_NODES quotas (Step 2a), never
#     heap, never the conn block;
#   - the emit payload copy (s_retry_emit_payload_own) and the emit slot-pin
#     record (s_slot_pin_heap): the same emit class's machinery;
#   - the stream-claim inbound hold (duct_new(uint8_t, frame.payload.size)):
#     stream-handler layer; its duct_stream_ctx_t carves in the session
#     block's streams region (Step 2a), the variable-width hold copy stays
#     the layer's one heap allocation until the map gives it a region —
#     "heap until Step 4" by the map's own amendment (duct-zerocopy-payload
#     §1 deletes the mechanism);
#   - the batch defer node: the session block's page-0 defer region under the
#     DUCT_SESSION_DEFER_BYTES budget (Step 2b), a sessionless conn's bind
#     window in that conn block's TX retry copy units — never heap;
#   - the timer ctx: folded into the timer wheel node (duct_timer_t.ctx,
#     Step 2b) — zero heap timer allocations;
#   - proto_state: protocol-owned heap, external forever by map §2;
#   - the worker-owned pass/scratch arrays (not slot memory).
#
# The session-path zero invariant (Step 2b): src/session/*.c names exactly the
# pool-owned allocations — the session pool struct, the join index and the
# join identity secret — and nothing else; duct_worker.c's session sites
# follow the allowances above.

foreach(var SRCDIR)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "conn_block_audit: ${var} is not set")
    endif()
endforeach()

set(violations "")

file(STRINGS "${SRCDIR}/conn/duct_conn.c" conn_lines)
set(ctor_news 0)
foreach(line IN LISTS conn_lines)
    if(line MATCHES "duct_vm_new|duct_olb_rx_new|duct_olb_tx_new|duct_vmq_mpsc_new|duct_vmq_mpsc_create")
        list(APPEND violations "duct_conn.c carves from the pool, not: ${line}")
    endif()
    if(line MATCHES "duct_new\\(")
        math(EXPR ctor_news "${ctor_news} + 1")
        if(NOT line MATCHES "duct_new\\(duct_conn_pool_t\\)")
            list(APPEND violations "duct_conn.c allocates outside the pool struct: ${line}")
        endif()
    endif()
endforeach()
if(NOT ctor_news EQUAL 1)
    list(APPEND violations "duct_conn.c lost its single pool-struct duct_new (${ctor_news} lines)")
endif()

set(member_files
    "${SRCDIR}/conn/duct_conn.c"
    "${SRCDIR}/duct_io.c"
    "${SRCDIR}/duct_worker.c"
    "${SRCDIR}/duct_frame_rx.c"
    "${SRCDIR}/duct_host.c"
    "${SRCDIR}/session/duct_session.c")
foreach(path IN LISTS member_files)
    file(STRINGS "${path}" lines)
    foreach(line IN LISTS lines)
        if(line MATCHES "conn->(rx_buf|tx_buf|inter_lane|ctx)|roamed->(rx_buf|tx_buf)")
            list(APPEND violations "${path}: ${line}")
        endif()
    endforeach()
endforeach()

set(wire_files
    "${SRCDIR}/conn/duct_conn.c"
    "${SRCDIR}/duct_io.c"
    "${SRCDIR}/duct_worker.c"
    "${SRCDIR}/duct_frame_rx.c"
    "${SRCDIR}/duct_wire.c"
    "${SRCDIR}/wire/duct_wire_tls.c")
foreach(path IN LISTS wire_files)
    file(STRINGS "${path}" lines)
    foreach(line IN LISTS lines)
        if(line MATCHES "create_parser|destroy_parser|create_codec|duct_wire_parser_create|duct_wire_parser_destroy|duct_new_secret\\(duct_wire_codec_t\\)")
            list(APPEND violations "${path}: per-conn parse and codec state is carved, not: ${line}")
        endif()
    endforeach()
endforeach()

file(STRINGS "${SRCDIR}/duct_worker.c" worker_lines)
set(codec_carves 0)
foreach(line IN LISTS worker_lines)
    if(line MATCHES "duct_conn_codec_slot")
        math(EXPR codec_carves "${codec_carves} + 1")
    endif()
endforeach()
if(codec_carves EQUAL 0)
    list(APPEND violations "duct_worker.c builds its codecs outside the conn block's codec slot")
endif()

# The engine park is the conn block's region: no heap alloc or free of a park
# anywhere the codec lives.
file(STRINGS "${SRCDIR}/wire/duct_wire_tls.c" tls_lines)
foreach(line IN LISTS worker_lines tls_lines)
    if(line MATCHES "^[ \t]*[*]")
        continue()
    endif()
    if(line MATCHES "engine_park" AND line MATCHES "duct_new|duct_del")
        list(APPEND violations "the engine park is carved in the conn block, not: ${line}")
    endif()
endforeach()

# The WFQ-full batch retry node is the conn block's region: duct_frame_rx.c's
# one heap allocation left is the io ctx's own scratch batch buffer.
file(STRINGS "${SRCDIR}/duct_frame_rx.c" frame_rx_lines)
foreach(line IN LISTS frame_rx_lines)
    if(line MATCHES "^[ \t]*[*]")
        continue()
    endif()
    if(line MATCHES "duct_new\\(" AND NOT line MATCHES "duct_new\\(char, scratch_bytes\\)")
        list(APPEND violations "duct_frame_rx.c allocates outside its scratch batch: ${line}")
    endif()
    if(line MATCHES "duct_del\\(node\\)")
        list(APPEND violations "a batch retry node is its conn block's region, not freed: ${line}")
    endif()
endforeach()

# B8-full: duct_worker.c's conn-path heap, pinned to the named allowances of
# the header comment. The counts run over the whole file (file(READ) +
# string(REGEX MATCHALL)): each whitelisted pattern carries an exact count,
# the forbidden shapes must be absent, and the total duct_new count must
# equal the whitelisted sum — any new conn-path heap allocation breaks it.
file(READ "${SRCDIR}/duct_worker.c" worker_raw)

function(duct_count var pattern)
    string(REGEX MATCHALL "${pattern}" _m "${worker_raw}")
    list(LENGTH _m ${var})
    set(${var} "${${var}}" PARENT_SCOPE)
endfunction()

duct_count(n_heap_retry_node "duct_new\\(retry_node_t\\)")
duct_count(n_heap_emit_copy "duct_new\\(uint8_t, out->payload\\.size\\)")
duct_count(n_heap_emit_pin "duct_new\\(duct_frame_ack_t\\)")
duct_count(n_heap_claim_hold "duct_new\\(uint8_t, frame\\.payload\\.size\\)")
duct_count(n_heap_defer_node "duct_new\\(uint8_t, node_sz")
duct_count(n_heap_hctx "duct_new\\(duct_stream_ctx_t\\)")
duct_count(n_heap_timer_ctx "duct_new\\(timer_ctx_t\\)")
duct_count(n_heap_pass_scratch "duct_new\\(duct_worker_dgram_batch_entry_t|duct_new\\(duct_listener_t \\*|duct_new\\(dgram_pass_t\\)|duct_new\\(vnet_train_t\\)")
duct_count(n_heap_worker_arrays "duct_new\\(duct_worker_t, n_workers\\)|duct_new\\(pthread_t, n_workers\\)")
duct_count(n_duct_new_all "duct_new\\(")
duct_count(n_region_take "s_retry_node_take\\(")
duct_count(n_region_drop "s_retry_node_drop\\(")
duct_count(n_dgram_block_raw_free "duct_del\\(node->dgram_tx\\.block\\)")
duct_count(n_frame_out_raw_free "duct_response_release_owned\\(&node->frame\\.out\\)")
duct_count(n_sess_region_take "s_retry_sess_node_take\\(")
duct_count(n_sess_region_release "s_retry_sess_node_release\\(")
duct_count(n_dgram_copy_heap "duct_new\\(uint8_t, total\\)")
duct_count(n_timer_fold_arm "s_timer_arm\\(")
duct_count(n_defer_region_take "s_defer_region_take\\(")

if(NOT n_heap_retry_node EQUAL 0)
    list(APPEND violations "the session-owned retry classes (emit, timer) carve in the session block's regions, no heap retry node remains (${n_heap_retry_node} duct_new(retry_node_t) sites)")
endif()
if(NOT n_heap_emit_copy EQUAL 1)
    list(APPEND violations "the emit payload copy is the class's one heap copy (${n_heap_emit_copy} sites)")
endif()
if(NOT n_heap_emit_pin EQUAL 1)
    list(APPEND violations "the emit slot-pin record is the class's one heap pin (${n_heap_emit_pin} sites)")
endif()
if(NOT n_heap_claim_hold EQUAL 1)
    list(APPEND violations "the stream-claim hold is the stream layer's one heap copy, named 'heap until Step 4' (${n_heap_claim_hold} sites)")
endif()
if(NOT n_heap_defer_node EQUAL 0)
    list(APPEND violations "the batch defer node carves in the session block's defer region or the conn block's copy units (${n_heap_defer_node} heap defer sites)")
endif()
if(NOT n_heap_hctx EQUAL 0)
    list(APPEND violations "the stream handler ctx carves in the session block's streams region (${n_heap_hctx} duct_new(duct_stream_ctx_t) sites)")
endif()
if(NOT n_heap_timer_ctx EQUAL 0)
    list(APPEND violations "the timer ctx folds into the timer wheel node (${n_heap_timer_ctx} duct_new(timer_ctx_t) sites)")
endif()
if(NOT n_dgram_copy_heap EQUAL 0)
    list(APPEND violations "a packed datagram's park copy comes from the conn's TX retry copy slots (${n_dgram_copy_heap} heap copies)")
endif()
if(NOT n_dgram_block_raw_free EQUAL 1)
    list(APPEND violations "every drain site frees a parked dgram's block through s_retry_dgram_block_release; the helper's own share drop is the one direct free (${n_dgram_block_raw_free} direct frees)")
endif()
if(NOT n_frame_out_raw_free EQUAL 1)
    list(APPEND violations "every drain site releases a parked frame's payload through s_retry_frame_out_release; the helper's own non-regional fallback is the one direct release (${n_frame_out_raw_free} direct releases)")
endif()
if(n_region_take LESS 6)
    list(APPEND violations "the five conn-owned retry saves take their nodes from the region (${n_region_take} s_retry_node_take sites, definition included)")
endif()
if(n_region_drop LESS 12)
    list(APPEND violations "the drain, the clear and the conn-lost discard drop their nodes through the region (${n_region_drop} s_retry_node_drop sites, definition included)")
endif()
if(NOT n_sess_region_take EQUAL 3)
    list(APPEND violations "the two session-owned retry saves take their nodes from the session block's regions (${n_sess_region_take} s_retry_sess_node_take sites, definition included)")
endif()
if(NOT n_sess_region_release EQUAL 3)
    list(APPEND violations "the session-owned drop arms return their nodes to the session block's regions (${n_sess_region_release} s_retry_sess_node_release sites, definition included)")
endif()
if(n_timer_fold_arm LESS 4)
    list(APPEND violations "every worker timer class arms through the folded payload (${n_timer_fold_arm} s_timer_arm sites, definition included)")
endif()
if(NOT n_defer_region_take EQUAL 2)
    list(APPEND violations "the session defer admission is the one taker of the page-0 defer region (${n_defer_region_take} s_defer_region_take sites, definition included)")
endif()
math(EXPR n_whitelisted
     "${n_heap_retry_node} + ${n_heap_emit_copy} + ${n_heap_emit_pin} + ${n_heap_claim_hold} + ${n_heap_defer_node} + ${n_heap_hctx} + ${n_heap_timer_ctx} + ${n_heap_pass_scratch} + ${n_heap_worker_arrays}")
if(NOT n_duct_new_all EQUAL n_whitelisted)
    list(APPEND violations "duct_worker.c carries duct_new sites beyond the named allowances (${n_duct_new_all} total, ${n_whitelisted} whitelisted)")
endif()

# The session-path zero invariant: src/session/*.c names exactly the
# pool-owned allocations and the join identity secret, nothing else.
file(READ "${SRCDIR}/session/duct_session.c" session_c_raw)
file(READ "${SRCDIR}/session/duct_join.c" session_join_raw)
file(READ "${SRCDIR}/session/duct_session_pool.c" session_pool_raw)
string(REGEX MATCHALL "duct_new\\(" n_session_news_all "${session_c_raw}${session_join_raw}${session_pool_raw}")
list(LENGTH n_session_news_all n_session_news)
string(REGEX MATCHALL "duct_new_secret\\(" n_session_secrets_all "${session_c_raw}${session_join_raw}${session_pool_raw}")
list(LENGTH n_session_secrets_all n_session_secrets)
string(REGEX MATCHALL "duct_vm_new" n_session_vms "${session_c_raw}${session_join_raw}${session_pool_raw}")
list(LENGTH n_session_vms n_session_vm_news)
if(NOT n_session_news EQUAL 2)
    list(APPEND violations "src/session/*.c names duct_new beyond the pool struct and the join index (${n_session_news} sites)")
endif()
if(NOT n_session_secrets EQUAL 1)
    list(APPEND violations "src/session/*.c names duct_new_secret beyond the join identity (${n_session_secrets} sites)")
endif()
if(NOT n_session_vm_news EQUAL 0)
    list(APPEND violations "src/session/*.c maps no VM of its own (${n_session_vm_news} duct_vm_new sites)")
endif()

# The pre-conn slab owns every pending dial and parked probe, and the device
# leg is carved in its conn's block with the io thread's one shared rx pool.
file(STRINGS "${SRCDIR}/duct_io.c" io_lines)
foreach(line IN LISTS io_lines)
    if(line MATCHES "^[ \t]*[*]")
        continue()
    endif()
    if(line MATCHES "duct_new\\(duct_pre_conn_t\\)|peek = duct_new|duct_del\\(pre_conn->probe.peek\\)")
        list(APPEND violations "a pre-conn record or its peek comes from the io slab, not: ${line}")
    endif()
    if(line MATCHES "device_leg_new|leg->rx_slots")
        list(APPEND violations "a device leg is carved in its conn block with the thread's shared pool, not: ${line}")
    endif()
endforeach()

if(violations)
    string(REPLACE ";" "\n" report "${violations}")
    message(FATAL_ERROR "conn_block_audit:\n${report}")
endif()
message(STATUS "conn_block_audit: no conn-path allocation or dead member reference")
