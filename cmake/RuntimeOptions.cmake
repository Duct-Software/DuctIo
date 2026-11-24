# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Duct Software, author: Constantin Papizh

function(duct_cache_uint name default doc)
    set(${name} "${default}" CACHE STRING "${doc}")
    if(NOT ${name} MATCHES "^[0-9]+$")
        message(FATAL_ERROR "${name} must be a non-negative integer")
    endif()
endfunction()

duct_cache_uint(DUCT_RUNTIME_MAX_CONNS 1024 "Maximum runtime conn/session slots")

# wsaevent waits on up to 64 handles, including the wake slot.
if(DUCT_EVENTS_MODEL STREQUAL "wsaevent" AND DUCT_RUNTIME_MAX_CONNS GREATER 63)
    set(DUCT_RUNTIME_MAX_CONNS 63 CACHE STRING "Maximum runtime conn/session slots" FORCE)
    message(STATUS "DuctIo: DUCT_EVENTS_MODEL=wsaevent clamps DUCT_RUNTIME_MAX_CONNS to 63")
endif()

duct_cache_uint(DUCT_RUNTIME_MAX_LISTENERS 32 "Maximum runtime listener slots")

# Darwin's poll() takes up to OPEN_MAX, 10240 descriptors a call, the waker's included.
if(DUCT_PLATFORM STREQUAL "darwin" AND DUCT_EVENTS_MODEL STREQUAL "poll")
    math(EXPR _duct_poll_set "${DUCT_RUNTIME_MAX_CONNS} + ${DUCT_RUNTIME_MAX_LISTENERS} + 1")
    if(_duct_poll_set GREATER 10240)
        message(FATAL_ERROR "DuctIo: Darwin's poll() takes at most 10240 descriptors a call; "
                            "DUCT_RUNTIME_MAX_CONNS + DUCT_RUNTIME_MAX_LISTENERS + 1 = ${_duct_poll_set}")
    endif()
endif()
duct_cache_uint(DUCT_SESSION_MAX_LEGS 16 "Maximum concurrent legs (bound conns) per session")
duct_cache_uint(DUCT_SESSION_MAX_STREAMS 128 "Maximum concurrent streams per multiplexed session")
duct_cache_uint(DUCT_CONN_TX_OLB_CAP 65536 "Per-conn TX OLB capacity in bytes, the floor a protocol's tx_olb_cap raises")
duct_cache_uint(DUCT_CONN_RX_OLB_CAP 196608 "Per-conn RX OLB capacity in bytes")
duct_cache_uint(DUCT_DGRAM_TX_OUTBOX_LANE_CAP 131072 "Per-worker lane capacity for a listener's dgram_tx_outbox, bytes")
duct_cache_uint(DUCT_DGRAM_SOCK_RCVBUF 8388608 "Kernel SO_RCVBUF requested for datagram sockets, bytes: what a socket holds while its RX slot pool is stalled, ~64 ms of a 1 Gbit/s socket")
duct_cache_uint(DUCT_DGRAM_SOCK_SNDBUF 4194304 "Kernel SO_SNDBUF requested for datagram listener sockets and a Windows x_udp_peer dial, bytes")
duct_cache_uint(DUCT_DGRAM_RX_BATCH 16 "Datagrams one recvmmsg call reads into RX slots")
duct_cache_uint(DUCT_DGRAM_RX_MAX_PASSES 16 "Batched reads one readiness notification may drain before yielding the io loop")
math(EXPR _DUCT_DGRAM_RX_SLOTS_DEFAULT "${DUCT_DGRAM_RX_BATCH} * ${DUCT_DGRAM_RX_MAX_PASSES}")
duct_cache_uint(DUCT_DGRAM_RX_SLOTS ${_DUCT_DGRAM_RX_SLOTS_DEFAULT} "Ceiling of datagram RX slots per worker, which the inter lane references instead of copying; the pool commits them DUCT_DGRAM_RX_BATCH at a time as a drain needs them and gives them back at rest, and one drain holds up to DUCT_DGRAM_RX_BATCH * DUCT_DGRAM_RX_MAX_PASSES")
duct_cache_uint(DUCT_DGRAM_TX_BATCH 16 "Datagrams one sendmmsg call takes off a connected peer socket's TX ring, the send-side counterpart of DUCT_DGRAM_RX_BATCH")
duct_cache_uint(DUCT_WIRE_CT_BUF_MAX 1065088 "Cleartext-buffer ceiling a sealed wire may declare (ct_buf_max), bytes: one engine record of duct_seal_pdu_ct_max plus a length-prefix inner frame of one mebibyte and its header. A wire whose buffer asks more is refused at creation; the per-worker ct chunk pool cuts its slots at this number")
duct_cache_uint(DUCT_WIRE_CT_CHUNKS 64 "Cleartext chunks a worker's ct pool holds at its ceiling; committed eight at a time as sealed conns take them, idle ones returned by the pool's own sweep")
duct_cache_uint(DUCT_DEVICE_RX_SPAN_MAX 9000 "Device read-span ceiling an io thread's shared device rx slot pool cuts its slots at, bytes: one slot serves one read of DUCT_DEVICE_RX_BATCH buffers of this span. A device whose rx_span asks more is refused at attach; every device the thread carries shares the one pool")
duct_cache_uint(DUCT_PRECONN_SLOTS 256 "Pre-conn records one io thread's fixed slab holds — parked probes and in-flight dials together, never a conn slot; a park or dial past it is refused as its allocation failing would have")
duct_cache_uint(DUCT_PRECONN_PEEK_MAX 4096 "Probe-peek tail one slab slot carries, bytes; a listener whose peek span asks more is refused at the bind")
duct_cache_uint(DUCT_CONN_PARK_CAP 65556 "Engine-egress park region every conn block carries behind its wire slots, bytes: two engine messages of the budget a sealed wire admits, flushed whole into the smallest TX ring. A wire whose park budget asks more is refused at creation")
duct_cache_uint(DUCT_CONN_RETRY_TX_NODES 192 "TX retry node slots every conn block carries for the backpressure classes that die with their conn (frame, fin, engine, close, dgram_tx), each one fixed-stride retry_node_t storage taken and freed by the owning worker alone; a save past the quota answers as its allocation failing would. The stream-owned emit and session-owned timer nodes stay heap — the map's '1b tail 2' amendment directs both to the session block")
duct_cache_uint(DUCT_CONN_RETRY_TX_COPIES 5 "Variable-width copy units of DUCT_CONN_RETRY_TX_COPY_MAX bytes every conn block carries for the frame answers and packed datagrams a park must own; a copy that fits a unit takes one, a wider copy spans the consecutive units it needs, first-fit from the lowest; a copy past the whole copy budget or without a free run answers as its allocation failing would, the payload refusing to park. Five units, not two: the client's ctl answers of churned streams park two-deep behind a stalled head and the third copy-needing park abandoned the leg whole — five is what the block's fit assert gives after the 192 node slots")
duct_cache_uint(DUCT_CONN_RETRY_TX_COPY_MAX 8192 "Byte span of one conn block's TX retry copy units; a copy wider than one unit spans consecutive units, all five covering a park just past a 40000-byte max_response datagram — the wire's full 65507-byte UDP ceiling cannot fit the block and refuses its park as its allocation failing would")
duct_cache_uint(DUCT_SESSION_RETRY_EMIT_NODES 30 "TX retry node slots every session block carries for the stream-owned emit class (fixed-stride retry_node_t storage taken and freed by the owning worker alone behind a page-0 map); a save past the quota answers as its allocation failing would, the stream failing with rc_again. The session block is 64 KB with the streams region behind page 0, so the emit and timer quotas together must fit what remains — the block-fit static_assert pins the sum; 30 of 264-byte slots is what the block gives after the streams region, and a voided emit (teardown empties the answer in place) holds its slot until its ticket resolves in turn, so the quota must carry a stalled head's churn, not just live answers")
duct_cache_uint(DUCT_SESSION_RETRY_TIMER_NODES 8 "TX retry node slots every session block carries for the session-owned timer class (one-shot timer fires parked behind their session's timer_hold output); a save past the quota loses the fire, same as its allocation failing would")
duct_cache_uint(DUCT_SESSION_DEFER_BYTES 14336 "Per-session defer budget the session block's page-0 tail carves for deferred frame-batch nodes, bytes, grain 64: a node spans the consecutive grain units it needs, first-fit from the lowest, released as its replay or discard ends. The budget bounds one slow session's share of the worker's defer queue; a batch past it is refused as its allocation failing would, the suffix dropped with rc_no_memory. Sized over a close-order run's parked inbound batches — a dozen whole 64-frame batches with fragmentation headroom; the fixed tail fills the hard page 0 so the block-fit assert stays 64896 of 65536 on every host")
duct_cache_uint(DUCT_DGRAM_BATCH_WAIT_US 50 "Latency budget a datagram batch may cost its first entry, microseconds; the worker solves its flush threshold against the measured entry rate for this")

if(DUCT_PLATFORM STREQUAL "darwin" AND DUCT_ARCH STREQUAL "aarch64")
    set(_DUCT_CACHELINE_DEFAULT 128)
else()
    set(_DUCT_CACHELINE_DEFAULT 64)
endif()
duct_cache_uint(DUCT_CACHELINE_SIZE ${_DUCT_CACHELINE_DEFAULT} "Cacheline size for false-sharing padding")

duct_cache_uint(DUCT_BUSY_SPIN_US 100 "Longest spin of an event loop on one idle stretch, microseconds, cut to DUCT_SPIN_GAP_CUTOFF_US; 0 = always park")
duct_cache_uint(DUCT_SPIN_GAP_CUTOFF_US 20 "Price of one park and wake of an event loop, microseconds of spin; no loop spins longer; 0 = always park")
if(DUCT_PLATFORM STREQUAL "darwin")
    set(_DUCT_THREAD_PINNING_DEFAULT 0)
else()
    set(_DUCT_THREAD_PINNING_DEFAULT 1)
endif()
duct_cache_uint(DUCT_THREAD_PINNING ${_DUCT_THREAD_PINNING_DEFAULT} "Bind io/worker threads to a cpu each; 0 leaves them schedulable")
duct_cache_uint(DUCT_PIN_IO_FIRST 1 "Pin-table slot order: 1 = io threads first, workers after; 0 = workers claim the table from slot 0 and io lines up after them, so the clean cores (isolcpus, or one per physical core) go to the bottleneck workers first and io gets its own core only when the table is deep enough -- a too-small table leaves io unpinned, shown as pin_fail")

duct_cache_uint(DUCT_TIMER_COALESCE_US 1000 "Timer coalescing window, microseconds)")
duct_cache_uint(DUCT_TIMER_HASH_BITS 6 "Timer hash table buckets = 2^N")
duct_cache_uint(DUCT_TIMER_TRIM_THRESHOLD 32 "Timer free-chain length before idle trim")

duct_cache_uint(DUCT_CORO_STACK_SLOTS 16 "Stackful coroutine slots per worker")
duct_cache_uint(DUCT_CORO_SL_SLOTS 64 "Stackless coroutine slots per worker")
duct_cache_uint(DUCT_CORO_STACK_BYTES 65536 "Stackful coroutine stack size, bytes")
duct_cache_uint(DUCT_CORO_CYCLE_QUOTA 8 "Stackful resumes per coop cycle")
duct_cache_uint(DUCT_ASYNC_CYCLE_QUOTA 16 "Stackless steps per coop cycle")

duct_cache_uint(DUCT_WFQ_QUOTA_FAST 128 "HI-tier WFQ quota per drain pass, frames")
duct_cache_uint(DUCT_WFQ_QUOTA_NORM 64 "NORM-tier WFQ quota per drain pass, frames")
duct_cache_uint(DUCT_WFQ_QUOTA_BG 8 "LO-tier WFQ quota per drain pass, frames")
duct_cache_uint(DUCT_WFQ_BYTE_QUOTA_NORM 65536 [[NORM-tier wire-byte budget,
shared by the I/O batch build and the worker-side drain quota]])

duct_cache_uint(DUCT_HANDSHAKE_MASK 1 "1 masks the ephemeral key leading every Noise handshake message with a value keyed by the pre-shared key and the message's closing AEAD tag, so the field reads as uniform bytes to an observer without the key; a peer built with the other value cannot complete a handshake with this one; 0 sends the raw X25519 point")

option(DUCT_ENABLE_RUNTIME_STATS
    "Compile in runtime debug counters (DUCT_RUNTIME_STATS)"
    OFF)
if(DUCT_ENABLE_RUNTIME_STATS)
    set(DUCT_RUNTIME_STATS 1)
else()
    set(DUCT_RUNTIME_STATS 0)
endif()

# Effective on Windows; ignored elsewhere.
option(DUCT_RIO_FORCE_DISABLE
    "Force duct_rio_resolve() to report RIO unavailable, for deterministic fallback-path testing"
    OFF)
if(DUCT_RIO_FORCE_DISABLE)
    set(DUCT_RIO_FORCE_DISABLE 1)
else()
    set(DUCT_RIO_FORCE_DISABLE 0)
endif()

option(DUCT_WITH_OPENSSL
    "Build the OpenSSL TLS 1.3 engine adapter and tests"
    OFF)

option(DUCT_WITH_NOISE
    "Build the Noise protocol engines (IKpsk2, XKpsk3) and tests"
    OFF)

include(CheckCSourceCompiles)
set(_duct_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${_duct_saved_required_flags} -Werror=attributes")
check_c_source_compiles("
struct duct_ptr_counted_by_probe {
    unsigned n;
    char *p __attribute__((counted_by(n)));
};
int main(void) {
    struct duct_ptr_counted_by_probe v = { 0u, (char *)0 };
    return (int)v.n + (v.p != (char *)0);
}
" DUCT_HAVE_PTR_COUNTED_BY)
set(CMAKE_REQUIRED_FLAGS "${_duct_saved_required_flags} -O2 -Wall -Wextra -Werror")
check_c_source_compiles("
#include <stdint.h>
__attribute__((zero_call_used_regs(\"used\")))
static uint64_t duct_zero_regs_probe(uint64_t a, uint64_t b) { return a ^ (b + 1u); }
__attribute__((noinline, zero_call_used_regs(\"used\")))
uint64_t duct_zero_regs_entry(uint64_t a, uint64_t b) { return duct_zero_regs_probe(a, b); }
int main(void) { return (int)duct_zero_regs_entry(1u, 2u); }
" DUCT_HAVE_ZERO_CALL_USED_REGS)
set(CMAKE_REQUIRED_FLAGS "${_duct_saved_required_flags}")
if(DUCT_HAVE_PTR_COUNTED_BY)
    set(DUCT_PTR_COUNTED_BY 1)
else()
    set(DUCT_PTR_COUNTED_BY 0)
endif()
if(DUCT_HAVE_ZERO_CALL_USED_REGS)
    set(DUCT_ZERO_CALL_USED_REGS 1)
else()
    set(DUCT_ZERO_CALL_USED_REGS 0)
endif()

include(CheckSymbolExists)
set(CMAKE_REQUIRED_FLAGS "${_duct_saved_required_flags} -std=gnu2x")
check_symbol_exists(memset_explicit "string.h" DUCT_HAVE_MEMSET_EXPLICIT)
check_symbol_exists(explicit_bzero  "string.h" DUCT_HAVE_EXPLICIT_BZERO)
set(CMAKE_REQUIRED_FLAGS "${_duct_saved_required_flags}")
if(DUCT_HAVE_MEMSET_EXPLICIT)
    set(DUCT_MEMSET_EXPLICIT 1)
else()
    set(DUCT_MEMSET_EXPLICIT 0)
endif()
if(DUCT_HAVE_EXPLICIT_BZERO)
    set(DUCT_EXPLICIT_BZERO 1)
else()
    set(DUCT_EXPLICIT_BZERO 0)
endif()

set(DUCT_BUILD_CONFIG_HEADER "${CMAKE_CURRENT_BINARY_DIR}/include/duct_build_config.h")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/duct_build_config.h.in"
    "${DUCT_BUILD_CONFIG_HEADER}"
    @ONLY)
set(DUCT_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
