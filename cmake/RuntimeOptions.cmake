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

set(DUCT_BUILD_CONFIG_HEADER "${CMAKE_CURRENT_BINARY_DIR}/include/duct_build_config.h")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/duct_build_config.h.in"
    "${DUCT_BUILD_CONFIG_HEADER}"
    @ONLY)
set(DUCT_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
