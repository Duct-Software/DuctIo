/*  SPDX-License-Identifier: Apache-2.0  */
/*  Copyright (c) 2026 Duct Software, author: Constantin Papizh  */

/** @file duct_core.h
 *  @brief Contracts, guards, header-backed allocation, portable builtins.
 *
 *  Owns guard macros, compile-time type/atomic-pointer predicates,
 *  @c duct_atomic_* wrappers, checked size math,
 *  allocation behind a header that counts holders and marks secrets, the locked pages a secret
 *  is allocated from, the scope-exit release and wipe built on the header, secure erase,
 *  big-endian fields, futex wait/wake,
 *  CPU topology helpers, plain-flag bitwise helpers, optional duct_rtstat_* counters and the
 *  timestamped log line the stderr notes are written through, with its variant that ends in
 *  the text of an error code, and the logger that takes those lines in place of the stream.
 *
 *  Header-only except @ref duct_log, @ref duct_logger_init and @ref duct_logger_fini, which
 *  src/duct_log.c implements, @ref duct_on_stop_signal, which src/duct.c implements,
 *  @ref duct_secret_adopt and @ref duct_secret_release, which os/duct_secret.c implements,
 *  @ref duct_localtime,
 *  which os/duct_time.c implements for every platform, and @ref duct_vm_new/reserve/lock/del,
 *  @ref duct_vm_discard, @ref duct_futex_wait/wake,
 *  @ref duct_thread_bind_cpu, @ref duct_thread_set_name,
 *  @ref duct_thread_block_stop_signals, @ref duct_stop_hook_arm/disarm,
 *  @ref duct_process_cpu and the page/cpu-count globals, which are
 *  implemented per platform.
 *
 *  Includes @c duct_types.h for the view types; that header includes nothing of this one.
 */

#ifndef DUCT_CORE_H
#define DUCT_CORE_H

#include "duct_build_config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "duct_types.h"

/** @brief Void-cast a return value; greppable marker for discarded results. */
#define duct_discard (void)

#if defined(__GNUC__) || defined(__clang__)
    /** @brief Compile-time argument null-check.
     *  Optimizes out runtime check on the same argument.
     */
    #define duct_nonnull(...) __attribute__((nonnull(__VA_ARGS__)))
#else
    #define duct_nonnull(...)
#endif

/** @brief Printf format check for a variadic function.
 *  @p f is the 1-based index of the format argument and @p a that of the first variadic one.
 *  MinGW takes its GNU printf attribute, other GCC and Clang builds @c format(printf), and a
 *  compiler with neither checks nothing.
 */
#if defined(__MINGW32__) && defined(__MINGW_GNU_PRINTF)
    #define duct_printf_like(f, a) __MINGW_GNU_PRINTF(f, a)
#elif defined(__GNUC__) || defined(__clang__)
    #define duct_printf_like(f, a) __attribute__((format(printf, f, a)))
#else
    #define duct_printf_like(f, a)
#endif

/** @brief Write one timestamped line to @p out.
 *  The line is the local time to the millisecond, @c YYYY-MM-DD HH:MM:SS.mmm, a blank, the text
 *  @p fmt formats and a newline. It goes whole to the installed @ref duct_logger_t, which takes
 *  the place of @p out, and otherwise to one @c fwrite on @p out, so that the lines of two threads
 *  on one stream stay whole. @p fmt carries no newline. A line is cut to 1023 bytes, newline
 *  included, and a cut message ends in @c "...". The stamp is the calling thread's wall clock,
 *  which follows a step of the system clock within a second.
 */
duct_nonnull(1, 2) void duct_log(FILE *out, const char *fmt, ...) duct_printf_like(2, 3);

/** @brief Process-wide receiver of the lines @c duct_log writes.
 *  While one is installed, @ref duct_log hands it every finished line in place of writing
 *  to the stream it was given. @c write runs on the thread that logs, on many threads at
 *  once, and takes the line as @c len bytes, stamp and newline included, with no terminator.
 *  It does not call @c duct_log.
 */
typedef struct {
    void (*write)(void *ctx, const char *line, size_t len); /**< Function taking one finished line. */
    void  *ctx;                                              /**< First argument of @c write. */
} duct_logger_t;

/** @brief Install @p logger as the process's logger.
 *  Replaces the logger that stands. A @p logger with a null @c write is ignored. The
 *  structure is referenced, not copied: it stays valid and unchanged until
 *  @ref duct_logger_fini.
 */
duct_nonnull(1) void duct_logger_init(const duct_logger_t *logger);

/** @brief Remove @p logger if it is the installed one.
 *  Any other installed logger stays, and with none installed @ref duct_log writes to its
 *  stream again. A thread inside @c write is not waited for: what @p logger and its @c ctx
 *  refer to outlives every thread that can log.
 */
duct_nonnull(1) void duct_logger_fini(const duct_logger_t *logger);

/** @brief Debug-only stderr note naming the file, line and function of the
 *  guard that fired. Compiled out of a release build. */
#if DUCT_DBG
#define duct_dbg_err duct_log(stderr, "Condition fail at [%s]:%d %s()", \
                              __FILE__, __LINE__, __func__);
/** @brief Debug-only stderr note naming the file, line and function of a bad
 *  exit, followed by a printf-formatted detail.
 *  The report of a switch case that is a bad exit, a case carrying no condition
 *  for @ref duct_do_if to take. Compiled out of a release build with its
 *  arguments unevaluated. */
#define duct_dbg_errf(fmt, ...) \
    duct_log(stderr, "Condition fail at [%s]:%d %s(): " fmt, \
             __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__)
#else
#define duct_dbg_err (void)0
#define duct_dbg_errf(fmt, ...) ((void)0)
#endif

/** @brief Stderr line, in every build, for a rare event nothing else reports: a
 *  declaration the runtime had to absorb, a pool that ran dry.
 *  @p fmt is a printf format without its newline and has to be a string literal:
 *  the macro puts @c "duct: " ahead of it, and @ref duct_log the stamp ahead of that
 *  and the newline behind.
 */
#define duct_diag(fmt, ...) \
    duct_log(stderr, "duct: " fmt __VA_OPT__(,) __VA_ARGS__)

/** @brief Runtime guard: if @p cond, execute @p expr.
 *  Standard runtime guard macro capturing error diagnostics.
 */
#define duct_do_if(cond, expr) ({ if (cond) { duct_dbg_err; expr; } })

/** @brief True if @p x and @p y have the same unqualified type. */
#define duct_is_types_compatible(x, y) \
    _Generic((typeof_unqual(x) *){}, typeof_unqual(y) *: 1, default: 0)

/** @brief True if @p p points at an @c _Atomic object with any const/volatile combo.
 *
 *  Backs the static_assert in the @c duct_atomic_* macros below.
 *  @c typeof_unqual hands back the pointee as one complete type, so
 *  re-qualifying it covers scalars, enums, structs and atomic pointers alike —
 *  four associations for the four const/volatile combinations.
 */
#define duct_is_atomic_ptr(p) (                                                 \
       duct_is_types_compatible((p), (typeof_unqual(*(p)) _Atomic *)0)          \
    || duct_is_types_compatible((p), (typeof_unqual(*(p)) _Atomic const *)0)    \
    || duct_is_types_compatible((p), (typeof_unqual(*(p)) _Atomic volatile *)0) \
    || duct_is_types_compatible((p), (typeof_unqual(*(p)) _Atomic const volatile *)0))


/**
 *  @name Type-checked atomic operations
 *  Tokens for @p mo / @p succ / @p below are expanded into @c memory_order_ prefix:
 *
 *  @li @c relaxed - no ordering with any other memory access — atomicity only. Fine for
 *                   independent counters/stats nobody synchronizes on.
 *  @li @c acquire - (load) later accesses in this thread can't move before it; pairs with
 *                   a release store to see everything the writer published before it —
 *                   "is this ready, and if so, is everything behind it visible too".
 *  @li @c release - (store) earlier accesses in this thread can't move after it, so a
 *                   matching acquire load sees them — publish a handle, buffer, generation.
 *  @li @c acq_rel - both, for a read-modify-write that consumes prior writes and publishes
 *                   its own in one step: CAS retry loops, a fetch_add used as a barrier.
 *  @li @c seq_cst - acq_rel plus one global total order shared by every seq_cst op on the
 *                   same objects. Reach for it only when acquire/release aren't enough to
 *                   reason about ordering across more than one location.
 *
 *  @p op is a bare token @c add / @c sub / @c or / @c and / @c xor, expanded into
 *  @c atomic_fetch_##op##_explicit. @note No wrapper for atomic_thread_fence provided.
 *  @{
 */

/** @brief Read side of an acquire/release handshake or a plain relaxed poll. */
#define duct_atomic_load(p, mo)                             \
    ({                                                      \
        auto _p = (p);                                      \
        static_assert(duct_is_atomic_ptr(_p),               \
            "duct_atomic_load: expected _Atomic pointer");  \
        atomic_load_explicit(_p, memory_order_##mo);        \
    })

/** @brief Write side of a release/acquire handshake or a plain relaxed publish. */
#define duct_atomic_store(p, v, mo)                         \
    ({                                                      \
        auto _p = (p);                                      \
        auto _v = (v);                                      \
        static_assert(duct_is_atomic_ptr(_p),               \
            "duct_atomic_store: expected _Atomic pointer"); \
        atomic_store_explicit(_p, _v, memory_order_##mo);   \
    })

/** @brief Atomic @c *p = *p op v, returns the value from @e before the op. */
#define duct_atomic_fetch(op, p, v, mo)                             \
    ({                                                              \
        auto _p = (p);                                              \
        auto _v = (v);                                              \
        static_assert(duct_is_atomic_ptr(_p),                       \
            "duct_atomic_fetch: expected _Atomic pointer");         \
        atomic_fetch_##op##_explicit(_p, _v, memory_order_##mo);    \
    })

/** @brief Atomically store @p v into @p p, return the value it replaced.
 *  Typical uses: test-and-set latches, drain-and-clear a counter/bitmask.
 */
#define duct_atomic_exchange(p, v, mo)                          \
    ({                                                          \
        auto _p = (p);                                          \
        auto _v = (v);                                          \
        static_assert(duct_is_atomic_ptr(_p),                   \
            "duct_atomic_exchange: expected _Atomic pointer");  \
        atomic_exchange_explicit(_p, _v, memory_order_##mo);    \
    })

/** @brief Atomic compare-and-swap.
 *  Stores @p des and returns true when @c *p == *exp; otherwise writes the
 *  current @c *p back into @p exp and returns false.
 *
 *  @param mode @c weak may fail spuriously even when @c *p == *exp — always
 *              call it inside a retry loop. @c strong never fails spuriously —
 *              one call is enough for a one-shot state transition, e.g. a
 *              fence-guarded open/close.
 *  @param succ Order on success, covers both the read and the write.
 *  @param fail Order on failure; must not be stronger than @p succ.
 */
#define duct_atomic_cas(mode, p, exp, des, succ, fail)                  \
    ({                                                                  \
        auto _p = (p);                                                  \
        auto _ep = (exp);                                               \
        auto _dv = (des);                                               \
        static_assert(duct_is_atomic_ptr(_p),                           \
            "duct_atomic_cas_" #mode ": expected _Atomic pointer");     \
        atomic_compare_exchange_##mode##_explicit(                      \
            _p, _ep, _dv, memory_order_##succ, memory_order_##fail);    \
    })
/** @} */

/**
 *  @name #if-safe feature probes
 *  Plain 0 on a compiler lacking the probe itself, so call sites skip the
 *  defined() dance.
 *  @{
 */
#ifdef __has_include
    #define duct_has_include(hdr) __has_include(hdr)
#else
    #define duct_has_include(hdr) 0
#endif

#ifdef __has_builtin
    #define duct_has_builtin(b) __has_builtin(b)
#else
    #define duct_has_builtin(b) 0
#endif

/** @} */

/** @brief Checked integer multiply / add / subtract.
 *  @return Nonzero on overflow, @p r is written regardless of result.
 */
#if duct_has_include(<stdckdint.h>)
    #include <stdckdint.h>
    #define duct_ckd_mul(r, a, b) ckd_mul((r), (a), (b))
    #define duct_ckd_add(r, a, b) ckd_add((r), (a), (b))
    #define duct_ckd_sub(r, a, b) ckd_sub((r), (a), (b))
#else
    #define duct_ckd_mul(r, a, b) __builtin_mul_overflow((a), (b), (r))
    #define duct_ckd_add(r, a, b) __builtin_add_overflow((a), (b), (r))
    #define duct_ckd_sub(r, a, b) __builtin_sub_overflow((a), (b), (r))
#endif

/** @brief Count trailing zero bits of @p v.
 *  @p v must be nonzero: the @c __builtin_ctzll fallback is UB on zero.
 */
#if duct_has_include(<stdbit.h>)
    #include <stdbit.h>
    #define duct_ctz_ull(v) stdc_trailing_zeros_ull(v)
#else
    #define duct_ctz_ull(v) ((unsigned)__builtin_ctzll(v))
#endif

/** @brief Hint the CPU to prefetch @p p for a future read. */
#if duct_has_builtin(__builtin_prefetch)
    #define duct_prefetch_read(p) __builtin_prefetch((p), 0, 0)
#else
    #define duct_prefetch_read(p) (duct_discard p)
#endif

/** @brief Mark a provably dead path. */
#ifdef unreachable
    #define duct_unreachable() unreachable()
#else
    #define duct_unreachable() __builtin_unreachable()
#endif

/** @brief Minimum of two values of the same type. */
#define duct_min(a, b)                                      \
    ({                                                      \
        static_assert(duct_is_types_compatible((a), (b)),   \
            "duct_min: incompatible argument types");       \
        auto _a = (a);                                      \
        auto _b = (b);                                      \
        _a < _b ? _a : _b;                                  \
    })

/** @brief Maximum of two values of the same type. */
#define duct_max(a, b)                                      \
    ({                                                      \
        static_assert(duct_is_types_compatible((a), (b)),   \
            "duct_max: incompatible argument types");       \
        auto _a = (a);                                      \
        auto _b = (b);                                      \
        _a > _b ? _a : _b;                                  \
    })

/** @brief Round @p value up to pow2 nonzero @p alignment.
 *  @return 0 on zero alignment, a non-pow2 @p alignment or size_t overflow.
 */
#define duct_align_up(value, alignment)                     \
    (size_t)({                                              \
        size_t _v = (value), _a = (alignment), _out = 0;    \
        if (_a != 0u && (_a & (_a - 1u)) == 0u) {           \
            size_t _m = _a - 1u, _rem = _v & _m;            \
            if (_rem == 0u)                                 \
                _out = _v;                                  \
            else if (duct_ckd_add(&_out, _v, _a - _rem))    \
                _out = 0u;                                  \
        }                                                   \
        _out;                                               \
    })

/** @brief Byte-count literals: @c kbytes(b) = b * 1024, @c mbytes(b) = b * 1024 * 1024. */
#define kbytes(b) ((size_t)(b) << 10)
#define mbytes(b) ((size_t)(b) << 20)

/** @brief Anonymous struct aligned and padded to the cache line.
 *  Declares one group among an enclosing struct's own members. @c alignas
 *  targets only a variable or a struct member in C.
 *
 *  @code
 *  typedef duct_cacheline_struct(int a; int b) foo;
 *
 *  typedef struct {
 *      duct_cacheline_struct(int c; int d);   // CL-0
 *      duct_cacheline_struct(int x; int y);   // CL-1
 *  } bar;
 *  @endcode
 */
#define duct_cacheline_struct(...) struct { alignas(duct_cacheline_size) __VA_ARGS__; }

/** @brief Cacheline-aligned struct with a named tail-padding field.
 *  @p _ext covers the bytes left past @c __VA_ARGS__, which may be empty.
 *  Fails to compile when @c __VA_ARGS__ fills the line exactly;
 *  @see duct_cacheline_struct for that case.
 */
#define duct_cacheline_struct_ext(_ext, ...)                                                \
    duct_cacheline_struct(__VA_ARGS__ __VA_OPT__(;)                                         \
        char _ext[                                                                          \
            duct_cacheline_size - (sizeof(struct { __VA_ARGS__ __VA_OPT__(;) })             \
                                   % duct_cacheline_size)                                   \
        ];                                                                                  \
        static_assert(                                                                      \
            (   sizeof(struct { __VA_ARGS__ __VA_OPT__(;) }) == 0u                          \
             || sizeof(struct { __VA_ARGS__ __VA_OPT__(;) }) % duct_cacheline_size != 0u),  \
            "fields fill the line: use duct_cacheline_struct()");                           \
    )

#ifdef __cplusplus
extern "C" {
#endif

/** @brief OS page size in bytes, cached once at process start. */
static inline size_t duct_page_size(void)
{
    extern size_t pg_size;
    return pg_size;
}

#ifdef _WIN32
    #include <winsock2.h>

    /** @brief Graceful shutdown and close of @p fd.
     *  Performs graceful send shutdown before closing descriptor to prevent
     *  abrupt RST abortion on Windows.
     */
    #define duct_sock_close(fd)                         \
        do {                                            \
            if (fd != duct_sock_bad) {                  \
                duct_sock_t _fd = (fd);                 \
                duct_discard shutdown(_fd, SD_SEND);    \
                duct_discard closesocket(_fd);          \
            }                                           \
        } while (0)

    typedef SOCKET duct_sock_t;
    constexpr auto duct_sock_bad = INVALID_SOCKET;
    #define duct_sock_err WSAGetLastError()
#else
    #include <errno.h>
    #include <sys/socket.h>
    #include <unistd.h>

    /** @brief Graceful shutdown + close. */
    #define duct_sock_close(fd)                         \
        do {                                            \
            if (fd != duct_sock_bad) {                  \
                duct_sock_t _fd = (fd);                 \
                duct_discard shutdown(_fd, SHUT_WR);    \
                duct_discard close(_fd);                \
            }                                           \
        } while (0)
    
    /** @brief Platform socket handle type, invalid-handle sentinel, and close() alias. */
    typedef int duct_sock_t;
    constexpr auto duct_sock_bad = -1;
    #define duct_sock_err errno
#endif

/** @brief Prepare an engine-created outgoing IP socket ahead of its connect.
 *  Runs on the dial's staging thread. Must be short, must not close the borrowed descriptor,
 *  and must not call back into the engine. False closes the socket without transmitting.
 *  Used by hosts that must exempt each tunnel socket from their system VPN.
 */
typedef bool (*duct_socket_prepare_fn)(void *ctx, duct_sock_t fd, int family);

#include "duct_str.h"

/** @brief Stamped log line to @p out: the message @p fmt formats, a colon and the text of error code @p err.
 *  @p fmt is a printf format without its newline and has to be a string literal: the macro
 *  pastes the colon and the text behind it. @p err is read as @ref duct_strerr reads it, is
 *  evaluated once and has no order against the message arguments, so an argument that
 *  changes @c errno stays out of a call whose @p err is @c errno.
 */
#define duct_log_err(out, err, fmt, ...) \
    duct_log(out, fmt ": %s", __VA_ARGS__ __VA_OPT__(,) \
             duct_strerr((int)(err), (char[duct_err_text_max]){}, duct_err_text_max))

/** @name Big-endian fields
 *  Read and written byte by byte, so any alignment and any host byte order serve,
 *  and a store writes exactly the bytes of its field.
 *  @{
 */
/** @brief Read the 16-bit field at @p p. */
duct_nonnull(1) static inline uint16_t duct_load_be16(const void *p)
{
    auto b = (const uint8_t *)p;
    return (uint16_t)((uint16_t)b[0] << 8u | b[1]);
}

/** @brief Read the 32-bit field at @p p. */
duct_nonnull(1) static inline uint32_t duct_load_be32(const void *p)
{
    auto b = (const uint8_t *)p;
    return (uint32_t)b[0] << 24u | (uint32_t)b[1] << 16u | (uint32_t)b[2] << 8u | b[3];
}

/** @brief Write @p v as the 16-bit field at @p p. */
duct_nonnull(1) static inline void duct_store_be16(void *p, uint16_t v)
{
    auto b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8u);
    b[1] = (uint8_t)v;
}

/** @brief Write @p v as the 32-bit field at @p p. */
duct_nonnull(1) static inline void duct_store_be32(void *p, uint32_t v)
{
    auto b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24u);
    b[1] = (uint8_t)(v >> 16u);
    b[2] = (uint8_t)(v >> 8u);
    b[3] = (uint8_t)v;
}
/** @} */

enum : unsigned { alloc_back_bits = 10 /**< Width of @c duct_alloc_hdr_t::back, bits. */ };
enum : unsigned { alloc_arena_bits = 3 /**< Width of @c duct_alloc_hdr_t::arena, bits. */ };

/** @brief Header in the 8 bytes below the object of every block @c duct_new and @c duct_new_secret answer.
 *  Written once at allocation, @c holders alone changing after. A free bit reads zero.
 */
typedef struct duct_alloc_hdr {
    uint16_t arena         : alloc_arena_bits; /**< Slot class of a secret in the secret arena, 1 to 7, and 0 for a block on the heap.
                                                *  Declared first, so that @c back sits at bits 3 to 12 and
                                                *  its byte offset is one mask of the word. */
    uint16_t back          : alloc_back_bits; /**< Offset from the calloc base to the object, in 8-byte units.
                                                *  1 in a slot of the arena, which starts at the header. */
    uint16_t secret        : 1;               /**< Mark of a @c duct_new_secret block. */
    uint16_t               : 2;               /**< Free 2 bits. */
    uint8_t _Atomic holders;                  /**< Holder count: 0 for one holder, 2 after the first
                                                *  @c duct_share. */
    uint8_t                : 8;               /**< Free byte. */
    uint32_t size;                            /**< Bytes asked for, count times element size. */
} duct_alloc_hdr_t;

/** @brief Largest alignment @c duct_new accepts, bytes. */
static constexpr size_t duct_alloc_align_max = 4096u;
static_assert(sizeof(duct_alloc_hdr_t) == 8u, "one header on every target");
static_assert(alignof(max_align_t) >= sizeof(duct_alloc_hdr_t), "calloc aligns to the header");
static_assert(offsetof(duct_alloc_hdr_t, holders) == 2u, "the count sits in the byte after the bit-fields");
static_assert(offsetof(duct_alloc_hdr_t, size) == 4u, "size takes the last word");
static_assert(duct_alloc_align_max / sizeof(duct_alloc_hdr_t) < 1u << alloc_back_bits,
              "the offset to the base fits its field");

/** @brief Move a fresh secret block into the secret arena and mark it secret.
 *  The step of @ref duct_new_secret after the allocation, taken on a block nothing has written
 *  yet. A block aligned to 8 of up to 4088 bytes moves into a zeroed slot of locked pages and the
 *  heap block is freed; any other block, any block the arena has no slot for, and every block of
 *  an AddressSanitizer build stay on the heap. Either way @c secret is set, so that @ref duct_del
 *  wipes it.
 *  @param obj  Object of a block @ref duct_new answered.
 *  @return The pointer to use from here on: @p obj, or the object of the slot.
 */
[[nodiscard]] duct_nonnull(1) void *duct_secret_adopt(void *obj);

/** @brief Wipe the secret block at @p obj, and give its slot back to the arena.
 *  The release step of @ref duct_del for a block marked secret. A block on the heap is wiped over
 *  its size and left for the caller to free; a slot of the arena is wiped with its header and goes
 *  back to its class.
 *  @return true when the caller frees the block, false when it was a slot.
 */
duct_nonnull(1) bool duct_secret_release(void *obj);

/** @brief Byte bound of the array type a @c duct_ptr_t points to.
 *  The smaller of @c PTRDIFF_MAX and 2^61 - 1, the largest array type every compiler of the tree
 *  takes. No real array comes near it.
 */
static constexpr uint64_t duct_ptr_bound_bytes =
    (uint64_t)PTRDIFF_MAX < (UINT64_MAX >> 3) ? (uint64_t)PTRDIFF_MAX : UINT64_MAX >> 3;

/** @brief Pointer to the array of @c T that @c duct_new answers when given a count.
 *  The type is @c T (*)[duct_ptr_bound_bytes / sizeof(T)], a bound only these pointers carry:
 *  the compiler refuses one from another element type, from a plain @c T * and from the address
 *  of a fixed-size array. The address of a variable length array converts without a word, and
 *  @ref duct_is_ptr stops it at the accessors. The pointer is never dereferenced as an array:
 *  @ref duct_at yields the elements, and @c p + off steps in whole arrays.
 *  A read-only view is @c duct_ptr_t(const T), which a writable array converts to;
 *  @c duct_ptr_t(T) a, b; declares two pointers.
 */
#define duct_ptr_t(T) typeof(T (*)[duct_ptr_bound_bytes / sizeof(T)])

/** @brief Zero @p n bytes at @p p in a way the compiler cannot remove.
 *  For key material and any other secret about to leave scope. A @c memset followed by an empty
 *  asm that takes @p p and clobbers memory, on every platform; @p p and @p n are evaluated once.
 */
#define duct_secure_zero(p, n)                                                              \
    ({                                                                                      \
        auto _zp = (p);                                                                     \
        memset(_zp, 0, (n));                                                                \
        __asm__ volatile("" : : "r"(_zp) : "memory");                                       \
    })

/** @brief Zeroed allocation of one @c T, or of an array of it, behind a header.
 *  With no count answers a @c T *; with a count, a @c duct_ptr_t of @c T, whose elements
 *  @ref duct_len counts from the header. The object is 8-aligned at least, its header,
 *  @c duct_alloc_hdr_t, in the 8 bytes below it.
 *
 *  @param T  Type to allocate.
 *  @param ...  Optional element count, 1 when left out, then optional alignment: 0 or left out
 *              is @c alignof(T), and one under 8 is raised to 8. A third argument stops the build.
 *
 *  @warning Release only with @ref duct_del or @ref duct_del_fn.
 *  @return @c nullptr on allocation failure, a size of 4 GiB or more, a count of 0, or an
 *          alignment that is no power of two or is past @c duct_alloc_align_max, whether the
 *          count and the alignment are constants or not.
 *
 *  @code
 *  auto p   = duct_new(duct_timer_t);         // a duct_timer_t *
 *  auto arr = duct_new(duct_frame_t, n);      // n elements
 *  auto buf = duct_new(duct_frame_t, n, 64);  // n elements, 64-byte aligned
 *  @endcode
 */
#define duct_new(T, ...)                                                                    \
    ({                                                                                      \
        size_t _va[] = { 0 __VA_OPT__(, __VA_ARGS__), 0, 0 };                               \
        constexpr size_t _vc = sizeof(_va) / sizeof(size_t) - 3u;                           \
        static_assert(_vc <= 2u, "duct_new takes a type, a count and an alignment");        \
        size_t _n    = _vc == 0u ? 1u : _va[1],                                             \
               _req  = _vc > 1u ? _va[2] : 0u,                                              \
               _al   = duct_max(_req ? _req : alignof(T), sizeof(duct_alloc_hdr_t)),        \
               _total = 0u;                                                                 \
        uint32_t _bytes = 0u;                                                               \
        unsigned char *_p = nullptr;                                                        \
        if (_n != 0u && (_req & (_req - 1u)) == 0u && _al <= duct_alloc_align_max           \
            && !duct_ckd_mul(&_bytes, _n, sizeof(T)) && !duct_ckd_add(&_total, _bytes, _al)) { \
            auto _raw = (unsigned char *)calloc(1u, _total);                                \
            if (_raw) {                                                                     \
                /* _al is a power of two: the round-up is a mask. */                        \
                _p = _al == sizeof(duct_alloc_hdr_t) ? _raw + sizeof(duct_alloc_hdr_t)      \
                   : (unsigned char *)(((size_t)_raw + sizeof(duct_alloc_hdr_t) + _al - 1u) & -_al); \
                auto _h = (duct_alloc_hdr_t *)(_p - sizeof(duct_alloc_hdr_t));              \
                _h->back = (size_t)(_p - _raw) / sizeof(duct_alloc_hdr_t);                  \
                _h->size = _bytes;                                                          \
            }                                                                               \
        }                                                                                   \
        _Generic((char (*)[_vc + 1u])nullptr, char (*)[1]: (T *)_p, default: (duct_ptr_t(T))_p); \
    })

/** @brief Zeroed allocation of @c T whose bytes the last @c duct_del wipes.
 *  Takes the arguments and answers as @ref duct_new. A block aligned to 8 of up to 4088 bytes sits
 *  in a slot of pages locked in RAM; a larger or wider-aligned block, one the system refuses a
 *  locked page for, and every block of an AddressSanitizer build sit on the heap. The wipe
 *  covers both.
 */
#define duct_new_secret(T, ...)                                                             \
    ({                                                                                      \
        auto _ns = duct_new(T __VA_OPT__(,) __VA_ARGS__);                                   \
        if (_ns)                                                                            \
            _ns = (typeof(_ns))duct_secret_adopt(_ns);                                      \
        _ns;                                                                                \
    })

/** @brief Test that the pointer @p p is a @c duct_ptr_t of its own element type.
 *  Holds, as an integer constant expression, for a @c duct_ptr_t of any element type, a read-only
 *  view included, and is 0 for another pointer to an array or to a pointer: the address of a
 *  fixed-size array, of a variable length array, a @c T **. A pointer to a scalar or a struct
 *  stops the build.
 */
#define duct_is_ptr(p)                                                                      \
    (duct_is_types_compatible((p), (duct_ptr_t(typeof((*(p))[0])))nullptr)                  \
     && _Generic(1 ? (int *)nullptr : (void *)((size_t)sizeof(*(p)) * 0u), int *: 1, default: 0))

/** @brief Elements of the array @p p, as a @c T *.
 *  A @c const @c T * for a @c duct_ptr_t of @c const @c T, nullptr for nullptr. Takes a
 *  @c duct_ptr_t only; any other pointer stops the build. Arithmetic on the elements goes through
 *  it, @c duct_at(p) + off.
 */
#define duct_at(p)                                                                          \
    ({                                                                                      \
        auto _ap = (p);                                                                     \
        static_assert(duct_is_ptr(_ap), "duct_at takes a duct_ptr_t");                      \
        (typeof(&(*_ap)[0]))(void *)_ap;                                                    \
    })

/** @brief Bytes of the array @p p, read from its header.
 *  The count times @c sizeof(T) that @c duct_new was given. Takes a @c duct_ptr_t only; any
 *  other pointer stops the build. @p p is not nullptr, a null array having no header.
 */
#define duct_byte_len(p)                                                                    \
    ({                                                                                      \
        auto _bl = (p);                                                                     \
        static_assert(duct_is_ptr(_bl), "duct_byte_len takes a duct_ptr_t");                \
        (size_t)((duct_alloc_hdr_t *)((uintptr_t)_bl - sizeof(duct_alloc_hdr_t)))->size;    \
    })

/** @brief Element count of the array @p p.
 *  Its @c duct_byte_len over @c sizeof(T); takes a @c duct_ptr_t only, and not nullptr.
 */
#define duct_len(p)                                                                         \
    ({                                                                                      \
        auto _lp = (p);                                                                     \
        duct_byte_len(_lp) / sizeof((*_lp)[0]);                                             \
    })

#define DUCT_VIEW_DECLARE(T, name) typedef struct { T *data; size_t size; } name;

#define duct_view(V, p, n)                                                           \
    ({                                                                                \
        static_assert(sizeof(*(p)) < duct_ptr_bound_bytes / 2u,                       \
            "duct_view takes an element pointer; a duct_ptr_t goes through duct_view_all"); \
        static_assert(_Generic((p), void *: 1, const void *: 1,                       \
            default: duct_is_types_compatible(&(p)[0],                               \
                        (*(V *)nullptr).data)),                                      \
            "duct_view element type differs from the view's");                        \
        (V){ (p), (n) };                                                              \
    })

#define duct_view_all(V, p)                                                           \
    ({                                                                                \
        auto _va = (p);                                                               \
        static_assert(duct_is_ptr(_va), "duct_view_all takes a duct_ptr_t");          \
        static_assert(duct_is_types_compatible(*duct_at(_va), *(*(V *)nullptr).data), \
            "duct_view_all element type differs from the view's");                    \
        (V){ duct_at(_va), duct_len(_va) };                                           \
    })

#define duct_view_widen(CV, v)                                                        \
    ({                                                                                \
        static_assert(sizeof(*(v).data) == sizeof(*(*(CV *)nullptr).data)              \
            && duct_is_types_compatible(*(v).data, *(*(CV *)nullptr).data),           \
            "duct_view_widen keeps the element type and drops writability alone");    \
        (CV){ (v).data, (v).size };                                                   \
    })

#define duct_view_slice(V, v, off, n)                                                 \
    ({                                                                                \
        V _vs = (v);                                                                  \
        static_assert(duct_is_types_compatible(*_vs.data, *(*(V *)nullptr).data),     \
            "duct_view_slice element type differs from the view's");                  \
        size_t _vo = (off), _vn = (n);                                                \
        assert(_vo + _vn <= _vs.size);                                                \
        (V){ _vs.data + _vo, _vn };                                                   \
    })

#define duct_view_len(v)   ({ auto _vl = (v); _vl.size; })
#define duct_view_byte_len(v) ({ auto _vb = (v); _vb.size * sizeof(*_vb.data); })
#define duct_view_at(v, i) ({ auto _vat = (v); assert((i) < _vat.size); _vat.data[(i)]; })

/** @brief Add a holder to the block @p p points at, and answer @p p.
 *  Written where @p p passes to the thread that becomes the holder, ahead of the hand-over, whose
 *  post publishes the count. Every holder ends with its own @ref duct_del, in any order on any
 *  thread. A block holds 255 at most; one more aborts. @p p is not nullptr.
 */
#define duct_share(p)                                                                       \
    ({                                                                                      \
        auto _sp = (p);                                                                     \
        auto _sh = &((duct_alloc_hdr_t *)((uintptr_t)_sp - sizeof(duct_alloc_hdr_t)))->holders; \
        if (duct_atomic_load(_sh, relaxed) == 0u)                                           \
            duct_atomic_store(_sh, (uint8_t)2u, relaxed);                                   \
        else {                                                                              \
            uint8_t _old = duct_atomic_fetch(add, _sh, (uint8_t)1u, relaxed);               \
            duct_fatal(_old == UINT8_MAX);                                                  \
        }                                                                                   \
        _sp;                                                                                \
    })

/** @brief Drop this holder's hold on the block @p ptr points at, and null @p ptr.
 *  The drop that leaves no holder wipes a @ref duct_new_secret block, then frees it or gives its
 *  slot back to the arena; the others only drop. A pointer copied without @ref duct_share holds
 *  nothing, and a @c duct_del through it is a second release. nullptr is ignored.
 *  @param ptr  Pointer lvalue from @ref duct_new or @ref duct_new_secret, or nullptr.
 *  @code
 *  duct_del(p);
 *  @endcode
 */
#define duct_del(ptr)                                                                       \
    do {                                                                                    \
        auto _d = (unsigned char *)(uintptr_t)(ptr);                                        \
        if (_d) {                                                                           \
            auto _h = (duct_alloc_hdr_t *)(_d - sizeof(duct_alloc_hdr_t));                  \
            if (duct_atomic_load(&_h->holders, relaxed) == 0u                               \
                || duct_atomic_fetch(sub, &_h->holders, (uint8_t)1u, acq_rel) == 1u) {      \
                if (!_h->secret || duct_secret_release(_d))                                 \
                    free(_d - (size_t)_h->back * sizeof(duct_alloc_hdr_t));                 \
            }                                                                               \
        }                                                                                   \
        (ptr) = nullptr;                                                                    \
    } while (0)

/** @brief Callback form of @c duct_del, for a @c void (*)(void *) slot.
 *  Nulls its own parameter alone.
 */
static inline void duct_del_fn(void *p) { duct_del(p); }

#if !defined(__has_attribute) || !__has_attribute(cleanup)
#error "duct_core.h needs the cleanup attribute: GCC 13+ or a Clang that takes C23"
#endif

/** @brief Cleanup handler of @c duct_auto_del, @p pp the address of the pointer variable. */
static inline void duct_auto_del_fn(void *pp) { duct_del_fn(*(void **)pp); }

/** @brief Attribute that releases the pointer variable it precedes with @c duct_del at the end of its scope.
 *  Runs on a return from the middle and on each pass of a loop body; it does not run on
 *  @c longjmp, @c abort or @c exit, nor for a @c handler_coro body closed while parked in
 *  @c duct_stream_emit_and_wait or @c duct_stream_emit_and_yield, whose stack is never resumed.
 *  @code
 *  duct_auto_del auto p = duct_new(duct_timer_t);
 *  @endcode
 */
#define duct_auto_del [[gnu::cleanup(duct_auto_del_fn)]]

/** @brief Hand over the pointer in the lvalue @p ptr, and null @p ptr.
 *  Answers the pointer, so a @c duct_auto_del variable moved from releases nothing.
 */
#define duct_move(ptr)                                                                      \
    ({                                                                                      \
        auto _mp = (ptr);                                                                   \
        (ptr) = nullptr;                                                                    \
        _mp;                                                                                \
    })

/** @brief Cleanup handler of @c duct_auto_zero, @p r the bytes to wipe. */
static inline void duct_auto_zero_fn(duct_view_u8 *r) { duct_secure_zero(r->data, r->size); }

/** @brief Declaration that wipes the variable or array @p name at the end of its scope.
 *  Written right after @p name; the wipe follows a return expression that reads @p name. Declares
 *  @c name##_zero_ and wipes @c sizeof(name) bytes through @c duct_secure_zero.
 *  @code
 *  uint8_t key[32];
 *  duct_auto_zero(key);
 *  @endcode
 */
#define duct_auto_zero(name)                                                                \
    [[gnu::cleanup(duct_auto_zero_fn)]] duct_view_u8 name##_zero_ =                         \
        { (uint8_t *)&(name), sizeof(name) }

/** @brief Declaration of a variable that is wiped at the end of its scope.
 *  @p T is its type, @c auto included, @p name its name, and the rest, when given, its
 *  initializer, braces and commas included. It stands for the declaration and the
 *  @c duct_auto_zero of @p name, so the wipe follows a return expression that reads the variable.
 *  @code
 *  duct_secret(ductun_key_t, key, {});
 *  duct_secret(auto, profile, ductun_profile_read(path));
 *  @endcode
 */
#define duct_secret(T, name, ...)                                                           \
    T name __VA_OPT__(= __VA_ARGS__);                                                       \
    duct_auto_zero(name)

/** @brief Declaration of an array that is wiped at the end of its scope.
 *  @p n is a constant count of @p T, @p name the array's name, and the rest, when given, its
 *  initializer. It stands for the declaration and the @c duct_auto_zero of @p name.
 *  @code
 *  duct_secret_array(uint8_t, dh, 32);
 *  @endcode
 */
#define duct_secret_array(T, name, n, ...)                                                  \
    T name[n] __VA_OPT__(= __VA_ARGS__);                                                    \
    duct_auto_zero(name)

/** @brief Anonymous private mapping: @c base / @c size pair for munmap. */
typedef struct duct_vm_handle {
    void  *base; /**< Mapping start, @c nullptr on failure. */
    size_t size; /**< Mapping size, rounded up to the page size. */
} duct_vm_handle_t;

/** @brief Map anonymous private read/write memory of at least @p size bytes.
 *
 *  Rounds up to the page size.
 *
 *  @return Handle with @c base and @c size on success;
 *          zeroed handle on failure.
 */
[[nodiscard]] duct_vm_handle_t duct_vm_new(size_t size);

/** @brief Reserve address space of at least @p size bytes that nothing can touch yet.
 *  Rounds up to the page size and commits no memory: the range stays inaccessible until
 *  @ref duct_vm_lock makes part of it usable. Release it with @ref duct_vm_del.
 *  @return Handle with @c base and @c size on success; zeroed handle on failure.
 */
[[nodiscard]] duct_vm_handle_t duct_vm_reserve(size_t size);

/** @brief Make the pages of [@p base, @p base + @p size) usable, zeroed and locked in RAM.
 *  @p base and @p size cover whole pages inside a @ref duct_vm_reserve range.
 *  @retval rc_ok         The range is readable, writable and locked.
 *  @retval rc_no_memory  The system refused a commit or the lock; the range is inaccessible
 *                        and unlocked again.
 */
[[nodiscard]] duct_nonnull(1) duct_result_t duct_vm_lock(void *base, size_t size);

/** @brief Unmap and zero @p h; safe on an already-zeroed handle. */
duct_nonnull(1) void duct_vm_del(duct_vm_handle_t *h);

/** @brief Give the pages of [@p base, @p base + @p size) back to the system,
 *  their contents with them.
 *  The range stays mapped and writable, and a later touch faults nothing; a byte
 *  read before its next write is undefined. @p base and @p size cover whole
 *  pages; a @p size of 0 does nothing. */
duct_nonnull(1) void duct_vm_discard(void *base, size_t size);

/** @brief Infinite timeout for @c duct_futex_wait. */
#define DUCT_TIMEOUT_INFINITE 0u

/** @brief Block while the @c uint32_t at @p addr still equals @p expected.
 *
 *  @param timeout_ms @ref DUCT_TIMEOUT_INFINITE to wait forever, else a bound.
 *  @retval true   Woken, or @p addr already differed at call time.
 *  @retval false  Timed out.
 */
duct_nonnull(1) bool duct_futex_wait(void *addr, uint32_t expected, uint32_t timeout_ms);

/** @brief Wake count that reaches every waiter. */
static constexpr uint32_t duct_futex_wake_all = (uint32_t)INT32_MAX;

/** @brief Wake up to @p count threads blocked in duct_futex_wait on @p addr. */
duct_nonnull(1) void duct_futex_wake(void *addr, uint32_t count);

/** @brief Shared shape of threads' spawn rendezvous.
 *
 *  Blocks until a spawned thread's own @p started word leaves 0 or @p timeout_ms
 *  elapses — one bounded @ref duct_futex_wait call with a single re-check.
 *
 *  @retval false  @p started is still 0 after the wait (timeout), or reads 2
 *                 (thread-side init failure).
 *  @retval true   @p started reads 1.
 */
duct_nonnull(1) static inline bool
duct_thread_started_wait(unsigned _Atomic *started, uint32_t timeout_ms)
{
    if (duct_atomic_load(started, acquire) == 0u) {
        duct_futex_wait(started, 0u, timeout_ms);
        if (duct_atomic_load(started, acquire) == 0u)
            return false;
    }
    return duct_atomic_load(started, acquire) == 1u;
}

/** @brief Arch spin-loop hint: x86 @c pause, ARM @c yield.
 *  Cuts memory-ordering penalty and power in busy-wait loops; the thread
 *  keeps its timeslice.
 */
static inline void duct_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#elif defined(__arm__) && (defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_8A__))
    __asm__ volatile("yield" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

/** @brief Online CPU count cached at process start; 0 if @c sysconf couldn't tell. */
static inline unsigned duct_cpu_online_count(void)
{
    extern unsigned cpu_count;
    return cpu_count;
}

/** @brief Bind the calling thread to CPU slot @p cpu_index.
 *  The slot indexes a candidate list computed at startup, one logical cpu per
 *  physical core, so two distinct slots never land on the same core. How
 *  strongly the placement holds is the platform implementation's.
 *
 *  @return the logical cpu the placement took; -1 once @p cpu_index runs past
 *          the candidate list, when that list is empty because the startup
 *          query failed, or when the platform call itself failed.
 */
[[nodiscard]] int duct_thread_bind_cpu(unsigned cpu_index);

/** @brief Name the calling thread @p name for debuggers and process listings.
 *  Best-effort: a name past the platform's limit, 15 bytes on Linux, leaves the
 *  thread's name as it was.
 */
duct_nonnull(1) void duct_thread_set_name(const char *name);

/** @brief Block SIGINT, SIGTERM and SIGHUP for the calling thread.
 *  Every thread the engine starts calls it at its start, so a stop signal reaches
 *  a thread of the host and never one of the engine's. A no-op on Windows.
 */
void duct_thread_block_stop_signals(void);

/** @brief Install the stop hook: handlers for the stop signals on POSIX, a console
 *  control handler on Windows.
 *  The hook of @ref duct_engine_stop_on_signals: each handler calls
 *  @ref duct_on_stop_signal. POSIX keeps the handlers it replaces for
 *  @ref duct_stop_hook_disarm, so a second call before one saves its own.
 */
void duct_stop_hook_arm(void);

/** @brief Take the stop hook out, restoring the POSIX handlers it replaced. */
void duct_stop_hook_disarm(void);

/** @brief Set the stop request: a stop signal arrived.
 *  The engine defines it and the platform hooks call it from a signal handler or
 *  the thread the system runs a console handler on.
 */
void duct_on_stop_signal(void);

/** @brief Processor time a process has spent, nanoseconds. */
typedef struct duct_cpu_time {
    uint64_t user_ns,   /**< Time in user mode over every thread the process ever ran. */
             kernel_ns; /**< Time in the kernel over the same threads. */
} duct_cpu_time_t;

/** @brief Read the calling process's user and kernel processor time.
 *  Exited threads are counted. Both fields are 0 where the operating system
 *  refuses the reading.
 */
duct_cpu_time_t duct_process_cpu(void);

struct tm;

/** @brief Break @p sec, seconds since the epoch, down into @p out as local time of the process's time zone.
 *  @return false for a second the platform refuses, with @p out unspecified.
 */
duct_nonnull(2) bool duct_localtime(int64_t sec, struct tm *out);

/** @brief Left-fold @p a, @p b and any varargs through @p combine expression.
 *
 *  @p combine is written in terms of the accumulator @c _r and current element
 *  @c _x, e.g. @c duct_or instantiates it as @c duct_flag_op(op, _r, _x).
 */
#define duct_va_fold(combine, a, b, ...)                                \
    ({                                                                  \
        typedef typeof(a) _T;                                           \
        _T _v[] = { (a), (b) __VA_OPT__(, __VA_ARGS__) };               \
        _T _r = _v[0];                                                  \
        for (unsigned _i = 1u; _i < sizeof(_v) / sizeof(_v[0]); ++_i)   \
        {                                                               \
            auto _x = _v[_i];                                           \
            _r = (combine);                                             \
        }                                                               \
        _r;                                                             \
    })

/** @brief Bitwise op on two plain flag values of the same type.
 *
 *  For @c _Atomic lvalues: load, combine, then fetch_or/fetch_and.
 */
#define duct_flag_op(op, a, b)                                          \
    ({                                                                  \
        auto _a = (a);                                                  \
        auto _b = (b);                                                  \
        static_assert(duct_is_types_compatible(_a, _b),                 \
            "duct_flag_op: incompatible argument types");               \
        typedef typeof(_a) _T;                                          \
        _T _out;                                                        \
        switch (sizeof(_T)) {                                           \
        case 1:  _out = (_T)(uint8_t)(_a op _b); break;                 \
        case 2:  _out = (_T)(uint16_t)(_a op _b); break;                \
        case 4:  _out = (_T)(uint32_t)(_a op _b); break;                \
        case 8:  _out = (_T)(uint64_t)(_a op _b); break;                \
        default: duct_unreachable();                                    \
        }                                                               \
        _out;                                                           \
    })

/** @brief Bitwise OR of two or more plain flag values. */
#define duct_or(a, b, ...) \
    duct_va_fold(duct_flag_op(|, _r, _x), a, b, __VA_ARGS__)

/** @brief Bitwise AND of two or more plain flag values. */
#define duct_and(a, b, ...) \
    duct_va_fold(duct_flag_op(&, _r, _x), a, b, __VA_ARGS__)

/** @brief Bitwise XOR of two or more plain flag values. */
#define duct_xor(a, b, ...) \
    duct_va_fold(duct_flag_op(^, _r, _x), a, b, __VA_ARGS__)

/** @brief Bitwise complement of a plain flag value. */
#define duct_not(x)                                 \
    ({                                              \
        auto _v = (x);                              \
        typedef typeof(_v) _T;                      \
        _T _out;                                    \
        switch (sizeof(_T)) {                       \
        case 1:  _out = (_T)(uint8_t)~_v; break;    \
        case 2:  _out = (_T)(uint16_t)~_v; break;   \
        case 4:  _out = (_T)(uint32_t)~_v; break;   \
        case 8:  _out = (_T)(uint64_t)~_v; break;   \
        default: duct_unreachable();                \
        }                                           \
        _out;                                       \
    })

/** @brief True when @p st has any bit from @p bit set: @c st & bit != 0. */
#define duct_has(st, bit)                   \
    ({                                      \
        auto _st = (st);                    \
        auto _bit = (bit);                  \
        duct_flag_op(&, _st, _bit) != 0;    \
    })

/** @brief True when all bits of @p mask are set in @p st: @c (st & mask) == mask. */
#define duct_has_all(st, mask)                  \
    ({                                          \
        auto _st = (st);                        \
        auto _mask = (mask);                    \
        duct_flag_op(&, _st, _mask) == (_mask); \
    })

/** @brief Constructor priority tiers for @c __attribute__((constructor(N))). */
#define DUCT_CTOR_PRI_CORE  101
#define DUCT_CTOR_PRI_STATE 102

/** @brief Abort if @p cond is true. */
#define duct_fatal(cond)                                \
    duct_do_if((cond),                                  \
        duct_log(stderr, "%s:%d: %s: fatal error: %s",  \
                 __FILE__, __LINE__, __func__, #cond);  \
        abort();                                        \
    )

/** @brief Runtime counters, real under @c DUCT_RUNTIME_STATS.
 *  The other build expands them to no-ops that leave their arguments
 *  unevaluated, so one call site serves both.
 */
#if DUCT_RUNTIME_STATS
    #define duct_rtstat_field(T, name) T name
    #define duct_rtstat_inc(var, delta) (duct_discard ((var) += (uint64_t)(delta)))
    #define duct_rtstat_max(var, val) duct_max((var), (val))
    /** @brief Atomic relaxed fetch-add; use for counters touched cross-thread. */
    #define duct_rtstat_atomic_inc(ptr, delta) \
        duct_atomic_fetch(add, (ptr), (uint64_t)(delta), relaxed)
    /** @brief Add @p delta to atomic counter @p field of @p obj, whose one writer
     *  is the calling thread: a relaxed load and store, no read-modify-write. */
    #define duct_rtstat_obj_inc(obj, field, delta)  duct_stat_add(obj, field, delta)
    /** @brief Raise atomic counter @p field of @p obj to @p val, on the same
     *  one-writer terms as @c duct_rtstat_obj_inc. */
    #define duct_rtstat_obj_max(obj, field, val)                                           \
        duct_atomic_store(&(obj)->field,                                                  \
                          duct_max(duct_atomic_load(&(obj)->field, relaxed), (uint64_t)(val)), \
                          relaxed)
#else
    #define duct_rtstat_field(T, name)
    #define duct_rtstat_inc(var, delta)             (duct_discard 0)
    #define duct_rtstat_max(var, val)               (duct_discard 0)
    #define duct_rtstat_atomic_inc(ptr, delta)      (duct_discard 0)
    #define duct_rtstat_obj_inc(obj, field, delta)  (duct_discard 0)
    #define duct_rtstat_obj_max(obj, field, val)    (duct_discard 0)
#endif /* DUCT_RUNTIME_STATS */

/** @brief Add @p delta to counter @p field of the statistics shard @p shard.
 *  A relaxed load and a relaxed store with no read-modify-write: the thread that owns
 *  @p shard is the only writer of its counters, and a second writer loses adds.
 *  @p shard is evaluated twice. @see duct_stats_shard
 */
#define duct_stat_add(shard, field, delta)                                              \
    duct_atomic_store(&(shard)->field,                                                  \
                      duct_atomic_load(&(shard)->field, relaxed) + (uint64_t)(delta),   \
                      relaxed)

#ifdef __cplusplus
}
#endif

#endif /* DUCT_CORE_H */