/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file alloc_test.c
 *  @brief Unit test for the allocation header and the scope-exit primitives of @c duct_core.h.
 *
 *  Driven straight against the macros, with no engine. @c calloc and @c free are
 *  recording functions here, defined ahead of the header so that the macros and the
 *  inline helpers it holds call them: a test sees which base was allocated, which
 *  block was released, how many times, and whether a secret already read zero when
 *  the release was made.
 *  Covers the header of a block and its alignment forms, the refusals, a
 *  secret's wipe, the holders of a shared block on one thread and across two,
 *  @c duct_del_fn, @c duct_auto_del with @c duct_move and @c duct_share,
 *  @c duct_auto_zero, the declarations @c duct_secret and @c duct_secret_array that
 *  stand for it, and @c duct_secure_zero.
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static atomic_uint s_frees;
static _Atomic(void *) s_based;
static _Atomic(void *) s_freed;
static _Atomic(const unsigned char *) s_watch;
static atomic_size_t s_watch_len;
static atomic_int s_wiped;

static void *s_calloc(size_t n, size_t size);
static void s_free(void *base);

#define calloc(n, size) s_calloc(n, size)
#define free(p) s_free(p)

#include "duct_core.h"

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

typedef struct {
    uint64_t a,
             b;
} obj_t;

/** @brief Answer what calloc answers, and keep it: the base every header must lead back to. */
static void *s_calloc(size_t n, size_t size)
{
    void *base = (calloc)(n, size);
    atomic_store(&s_based, base);
    return base;
}

/** @brief Record the release of the block at @p base: how many, which, and, if a block is
 *  watched, whether its bytes read zero at this moment. */
static void s_free(void *base)
{
    auto watch = atomic_exchange(&s_watch, nullptr);
    if (watch) {
        bool zero = true;
        for (size_t i = 0u; i < atomic_load(&s_watch_len); ++i)
            zero = zero && watch[i] == 0u;
        atomic_store(&s_wiped, zero);
    }
    atomic_store(&s_freed, base);
    atomic_fetch_add(&s_frees, 1u);
    (free)(base);
}

/* The header of the block whose object is at p, in the 8 bytes below it. */
static duct_alloc_hdr_t *s_hdr(const void *p)
{
    return (duct_alloc_hdr_t *)((uintptr_t)p - sizeof(duct_alloc_hdr_t));
}

/* Bytes from the calloc base up to the object. */
static size_t s_back(const void *p)
{
    return (size_t)s_hdr(p)->back * sizeof(duct_alloc_hdr_t);
}

/* True when the header in memory equals one built here from its named fields alone, with the
 * count at 0: the holes read zero, whatever bits the compiler gave them. */
static bool s_header_clean(const void *p, bool secret)
{
    auto h = s_hdr(p);
    duct_alloc_hdr_t ref;
    memset(&ref, 0, sizeof ref);
    ref.arena = h->arena;
    ref.back = h->back;
    ref.secret = secret;
    ref.size = h->size;
    return memcmp(h, &ref, sizeof ref) == 0;
}

static unsigned s_holders(const void *p)
{
    return duct_atomic_load(&s_hdr(p)->holders, relaxed);
}

static void s_watch_set(const void *p, size_t n)
{
    atomic_store(&s_wiped, -1);
    atomic_store(&s_watch_len, n);
    atomic_store(&s_watch, (const unsigned char *)p);
}

static bool s_zero(const void *p, size_t n)
{
    for (size_t i = 0u; i < n; ++i)
        if (((const unsigned char *)p)[i] != 0u)
            return false;
    return true;
}

/* A heap secret is gone after its release and the recorder saw it read zero at the free; a slot of the
 * arena stays mapped, so its bytes are read where they were. */
static bool s_released_zero(const unsigned char *at, size_t n, bool arena)
{
    return arena ? s_zero(at, n) : atomic_load(&s_wiped) == 1;
}

static int t_single(void)
{
    auto p = duct_new(obj_t);
    CHECK(p, "duct_new answers a block");
    CHECK(((uintptr_t)p & 7u) == 0u, "the object sits on 8");
    CHECK(p->a == 0u && p->b == 0u, "the object is zeroed");
    auto h = s_hdr(p);
    CHECK(h->size == sizeof(obj_t), "the header holds the bytes asked for");
    CHECK(s_back(p) == sizeof(duct_alloc_hdr_t), "an object on 8 sits right behind its header");
    CHECK(s_header_clean(p, false) && !h->secret, "a plain block carries no flag");
    CHECK(s_holders(p) == 0u, "a new block has one holder, counted 0");
    void *base = atomic_load(&s_based);
    unsigned before = atomic_load(&s_frees);
    duct_del(p);
    CHECK(!p, "duct_del nulls the variable");
    CHECK(atomic_load(&s_frees) == before + 1u && atomic_load(&s_freed) == base,
          "the release gets the base calloc returned, once");

    obj_t *none = nullptr;
    duct_del(none);
    CHECK(!none && atomic_load(&s_frees) == before + 1u, "duct_del of nullptr releases nothing");
    return 0;
}

static int t_array(void)
{
    auto a = duct_new(uint32_t, 10);
    CHECK(a && s_zero(a, 40u), "a count of 10 gives 10 zeroed elements");
    CHECK(s_hdr(a)->size == 40u, "the header holds count times element size");
    duct_del(a);

    auto b = duct_new(char, 33);
    CHECK(b && s_zero(b, 33u) && s_hdr(b)->size == 33u, "a count of 33 chars is 33 bytes");
    duct_del(b);
    return 0;
}

static int t_typed(void)
{
    auto one = duct_new(obj_t);
    static_assert(_Generic(one, obj_t *: true, default: false), "duct_new(T) answers a T *");
    auto words = duct_new(uint32_t, 10);
    static_assert(_Generic(words, duct_ptr_t(uint32_t): true, default: false),
                  "duct_new(T, n) answers a duct_ptr_t(T)");
    static_assert(duct_is_ptr(words), "an array of ours passes duct_is_ptr");
    static_assert(_Generic(duct_at(words), uint32_t *: true, default: false), "duct_at answers a T *");
    CHECK(words && duct_len(words) == 10u && duct_byte_len(words) == 40u,
          "the header gives the count and the bytes");

    uint32_t *elements = duct_at(words);
    for (unsigned i = 0u; i < 10u; ++i)
        elements[i] = i * 3u;
    duct_ptr_t(const uint32_t) view = words;
    static_assert(_Generic(duct_at(view), const uint32_t *: true, default: false),
                  "a read-only view yields const elements");
    CHECK(duct_len(view) == 10u && duct_at(view)[9] == 27u, "a read-only view reads the same array");
    duct_del(words);
    CHECK(!words, "duct_del nulls an array variable");
    duct_del(one);

    auto wide = duct_new(obj_t, 3);
    CHECK(wide && duct_len(wide) == 3u && duct_byte_len(wide) == 3u * sizeof(obj_t),
          "a count is of elements, not of bytes");
    duct_del(wide);

    auto aligned = duct_new(uint8_t, 100, 64);
    CHECK(aligned && duct_len(aligned) == 100u && ((uintptr_t)duct_at(aligned) & 63u) == 0u,
          "an aligned array reports its count and sits on its alignment");
    duct_del(aligned);

    duct_ptr_t(int) x = duct_new(int, 3), y = duct_new(int, 5);
    CHECK(x && y && duct_len(x) == 3u && duct_len(y) == 5u, "two arrays declared together are both pointers");
    duct_del(x);
    duct_del(y);

    auto pointers = duct_new(obj_t *, 4);
    static_assert(_Generic(duct_at(pointers), obj_t **: true, default: false),
                  "an array of pointers yields pointers to pointers");
    CHECK(pointers && duct_len(pointers) == 4u && duct_byte_len(pointers) == 4u * sizeof(obj_t *),
          "an element that is a pointer counts as one element");
    duct_del(pointers);

    auto key = duct_new_secret(uint8_t, 32);
    static_assert(_Generic(key, duct_ptr_t(uint8_t): true, default: false), "a secret array is a duct_ptr_t too");
    CHECK(key && duct_len(key) == 32u && s_hdr(key)->secret, "a secret array carries its count and its mark");
    memset(duct_at(key), 0xcd, 32u);
    s_watch_set(key, 32u);
    auto key_at = (const unsigned char *)duct_at(key);
    bool key_arena = s_hdr(key)->arena != 0u;
    duct_del(key);
    CHECK(s_released_zero(key_at, 32u, key_arena), "a secret array is wiped whole");
    return 0;
}

#define ALIGN_CASE(al)                                                                      \
    do {                                                                                    \
        auto p = duct_new(uint8_t, 100, (al));                                              \
        CHECK(p && ((uintptr_t)p & ((al) - 1u)) == 0u, "the object sits on its alignment"); \
        CHECK(s_zero(p, 100u), "the object is zeroed");                                     \
        CHECK(s_hdr(p)->size == 100u && s_header_clean(p, false), "the header holds the size alone"); \
        CHECK((al) <= 8u ? s_back(p) == 8u : s_back(p) >= 8u && s_back(p) <= (al),          \
              "back leads to the base within the spare");                                   \
        memset(p, 0xa5, 100u);                                                              \
        void *base = atomic_load(&s_based);                                                 \
        duct_del(p);                                                                        \
        CHECK(atomic_load(&s_freed) == base, "the release gets the base calloc answered");  \
    } while (0)

static int align_run(size_t al)
{
    auto p = duct_new(uint8_t, 100, al);
    CHECK(p && ((uintptr_t)p & (al - 1u)) == 0u, "a run-time alignment holds");
    memset(p, 0xa5, 100u);
    void *base = atomic_load(&s_based);
    duct_del(p);
    CHECK(atomic_load(&s_freed) == base, "the release gets the base calloc answered");
    return 0;
}

static int t_place(void)
{
    for (size_t al = 8u; al <= duct_alloc_align_max; al *= 2u)
        for (size_t n = 1u; n <= 300u; ++n) {
            auto p = duct_new(uint8_t, n, al);
            CHECK(p && ((uintptr_t)p & (al - 1u)) == 0u, "an object of any size sits on its alignment");
            CHECK(s_back(p) >= 8u && s_back(p) <= al, "back stays within the spare");
            void *base = atomic_load(&s_based);
            memset(p, 0xa5, n);
            duct_del(p);
            CHECK(atomic_load(&s_freed) == base, "the release gets the base calloc answered");
        }
    return 0;
}

static int t_align(void)
{
    ALIGN_CASE(8u);
    ALIGN_CASE(16u);
    ALIGN_CASE(64u);
    ALIGN_CASE(4096u);
    ALIGN_CASE(4u);

    for (size_t al = 8u; al <= duct_alloc_align_max; al *= 2u)
        if (align_run(al))
            return 1;

    typedef struct {
        alignas(64) uint8_t v[64];
    } wide_t;
    auto w = duct_new(wide_t);
    CHECK(w && ((uintptr_t)w & 63u) == 0u && s_hdr(w)->size == sizeof(wide_t),
          "a type aligned to 64 is placed on 64");
    duct_del(w);
    return 0;
}

static void *refuse(size_t n, size_t al)
{
    return duct_new(uint8_t, n, al);
}

static void *refuse_wide(size_t n)
{
    return duct_new(obj_t, n);
}

static int t_refuse(void)
{
    unsigned before = atomic_load(&s_frees);
    CHECK(!refuse(0u, 0u), "a count of 0 answers nullptr");
    CHECK(!refuse(100u, 24u), "an alignment that is no power of two answers nullptr");
    CHECK(!refuse(100u, 2u * duct_alloc_align_max), "an alignment past the cap answers nullptr");
    CHECK(!duct_new(uint8_t, 0), "a constant count of 0 answers nullptr");
    CHECK(!duct_new(uint8_t, 100, 24), "a constant alignment that is no power of two answers nullptr");
    CHECK(!duct_new(uint8_t, 100, 2 * duct_alloc_align_max), "a constant alignment past the cap answers nullptr");
    CHECK(!refuse(SIZE_MAX, 0u), "a size_t count that overflows the size answers nullptr");
    CHECK(!refuse_wide(SIZE_MAX / sizeof(obj_t) + 1u), "a product past size_t answers nullptr");
#if SIZE_MAX > UINT32_MAX
    CHECK(!refuse((size_t)UINT32_MAX + 1u, 0u), "4 GiB or more answers nullptr");
    CHECK(!refuse_wide(UINT32_MAX / sizeof(obj_t) + 1u), "a product past 4 GiB answers nullptr");
#endif
    auto p = refuse(100u, 0u);
    CHECK(p && s_header_clean(p, false), "an alignment of 0 asks for the type's own");
    void *q = p;
    duct_del(q);
    CHECK(atomic_load(&s_frees) == before + 1u, "a refusal allocates nothing to release");
    return 0;
}

static int t_secret(void)
{
    auto s = duct_new_secret(obj_t);
    CHECK(s && s_hdr(s)->secret && s_header_clean(s, true), "a secret block is marked");
    memset(s, 0xab, sizeof *s);
    s_watch_set(s, sizeof *s);
    auto s_at = (const unsigned char *)s;
    bool s_arena = s_hdr(s)->arena != 0u;
    duct_del(s);
    CHECK(s_released_zero(s_at, sizeof(obj_t), s_arena), "a secret reads zero when the release is made");

    auto plain = duct_new(obj_t);
    memset(plain, 0xab, sizeof *plain);
    s_watch_set(plain, sizeof *plain);
    duct_del(plain);
    CHECK(atomic_load(&s_wiped) == 0, "a plain block is released as it stands");

    auto key = duct_new_secret(uint8_t, 32, 64);
    CHECK(key && ((uintptr_t)key & 63u) == 0u && s_hdr(key)->secret && s_header_clean(key, true)
              && s_back(key) >= 8u && s_back(key) <= 64u,
          "a secret takes a count and an alignment too");
    memset(key, 0xcd, 32u);
    s_watch_set(key, 32u);
    duct_del(key);
    CHECK(atomic_load(&s_wiped) == 1, "an aligned secret is wiped whole");
    return 0;
}

static int t_share(void)
{
    unsigned before = atomic_load(&s_frees);
    auto p = duct_new(obj_t);
    auto q = duct_share(p);
    CHECK(q == p && s_holders(p) == 2u, "the first share makes two holders and answers the pointer");
    auto r = duct_share(p);
    CHECK(r == p && s_holders(p) == 3u, "a later share adds one");
    duct_del(q);
    CHECK(!q && s_holders(p) == 2u && atomic_load(&s_frees) == before, "a drop that leaves holders only drops");
    duct_del(r);
    CHECK(s_holders(p) == 1u && atomic_load(&s_frees) == before, "the last holder is counted 1");
    duct_del(p);
    CHECK(atomic_load(&s_frees) == before + 1u, "the last drop releases the block once");

    auto s = duct_new_secret(obj_t);
    memset(s, 0xee, sizeof *s);
    auto keep = duct_share(s);
    s_watch_set(s, sizeof *s);
    auto kept_at = (const unsigned char *)keep;
    bool kept_arena = s_hdr(keep)->arena != 0u;
    duct_del(s);
    CHECK(atomic_load(&s_wiped) == -1 && keep->a != 0u, "a drop that leaves a holder wipes nothing");
    duct_del(keep);
    CHECK(s_released_zero(kept_at, sizeof(obj_t), kept_arena), "the last drop of a shared secret wipes it");
    return 0;
}

static constexpr unsigned handoffs = 2000u;
static _Atomic(obj_t *) s_slot;

static void *s_taker([[maybe_unused]] void *arg)
{
    for (unsigned i = 0u; i < handoffs; ++i) {
        obj_t *p;
        while (!(p = atomic_exchange_explicit(&s_slot, nullptr, memory_order_acquire)))
            sched_yield();
        duct_del(p);
    }
    return nullptr;
}

static int t_threads(void)
{
    unsigned before = atomic_load(&s_frees);
    pthread_t t;
    CHECK(pthread_create(&t, nullptr, s_taker, nullptr) == 0, "a thread starts");
    for (unsigned i = 0u; i < handoffs; ++i) {
        auto p = duct_new(obj_t);
        while (atomic_load_explicit(&s_slot, memory_order_acquire))
            sched_yield();
        atomic_store_explicit(&s_slot, duct_share(p), memory_order_release);
        duct_del(p);
    }
    pthread_join(t, nullptr);
    CHECK(atomic_load(&s_frees) == before + handoffs, "two threads drop every block's two holds, one release each");
    return 0;
}

static int t_del_fn(void)
{
    unsigned before = atomic_load(&s_frees);
    auto p = duct_new(obj_t);
    duct_discard duct_share(p);
    void (*drop)(void *) = duct_del_fn;
    drop(p);
    CHECK(s_holders(p) == 1u && atomic_load(&s_frees) == before, "duct_del_fn drops one hold");
    drop(p);
    CHECK(atomic_load(&s_frees) == before + 1u, "duct_del_fn on the last hold releases the block");
    return 0;
}

static int s_early(bool leave)
{
    duct_auto_del auto p = duct_new(obj_t);
    p->a = 1u;
    if (leave)
        return 1;
    return 2;
}

static obj_t *s_make(bool fail)
{
    duct_auto_del auto p = duct_new(obj_t);
    if (!p)
        return nullptr;
    p->a = 7u;
    if (fail)
        return nullptr;
    return duct_move(p);
}

static size_t s_early_array(bool leave)
{
    duct_auto_del auto a = duct_new(uint32_t, 8);
    if (leave)
        return duct_len(a);
    return 0u;
}

static duct_ptr_t(uint32_t) s_make_array(bool fail)
{
    duct_auto_del auto a = duct_new(uint32_t, 6);
    if (!a || fail)
        return nullptr;
    duct_at(a)[5] = 9u;
    return duct_move(a);
}

static const unsigned char *s_scoped_at;
static bool s_scoped_arena;

static void s_scoped_secret(void)
{
    duct_auto_del auto s = duct_new_secret(obj_t);
    memset(s, 0xcd, sizeof *s);
    s_watch_set(s, sizeof *s);
    s_scoped_at = (const unsigned char *)s;
    s_scoped_arena = s_hdr(s)->arena != 0u;
}

static int t_auto_del(void)
{
    unsigned before = atomic_load(&s_frees);
    CHECK(s_early(true) == 1 && atomic_load(&s_frees) == before + 1u, "a return from the middle releases");
    CHECK(s_early(false) == 2 && atomic_load(&s_frees) == before + 2u, "the end of the function releases");
    {
        duct_auto_del auto p = duct_new(obj_t);
        p->a = 1u;
    }
    CHECK(atomic_load(&s_frees) == before + 3u, "the end of a block releases");
    for (unsigned i = 0u; i < 5u; ++i) {
        duct_auto_del auto p = duct_new(obj_t);
        p->a = i;
    }
    CHECK(atomic_load(&s_frees) == before + 8u, "each pass of a loop body releases");

    s_scoped_secret();
    CHECK(s_released_zero(s_scoped_at, sizeof(obj_t), s_scoped_arena), "a secret is wiped at scope exit");

    before = atomic_load(&s_frees);
    CHECK(!s_make(true) && atomic_load(&s_frees) == before + 1u, "a failure after the allocation releases");
    auto kept = s_make(false);
    CHECK(kept && kept->a == 7u && s_holders(kept) == 0u && atomic_load(&s_frees) == before + 1u,
          "duct_move hands the block out and disarms the release");
    duct_del(kept);

    auto src = duct_new(obj_t);
    auto dst = duct_move(src);
    CHECK(!src && dst, "duct_move nulls its source and answers the pointer");
    duct_del(dst);

    before = atomic_load(&s_frees);
    CHECK(s_early_array(true) == 8u && atomic_load(&s_frees) == before + 1u,
          "a return from the middle releases an array, its count read ahead of the release");
    CHECK(s_early_array(false) == 0u && atomic_load(&s_frees) == before + 2u, "the end of the function releases an array");
    CHECK(!s_make_array(true) && atomic_load(&s_frees) == before + 3u, "a failure after an array was made releases it");
    auto made = s_make_array(false);
    CHECK(made && duct_len(made) == 6u && duct_at(made)[5] == 9u && atomic_load(&s_frees) == before + 3u,
          "duct_move hands an array out with its count");
    duct_del(made);

    before = atomic_load(&s_frees);
    {
        duct_auto_del auto outer = duct_new(obj_t);
        {
            duct_auto_del auto inner = duct_share(outer);
            CHECK(inner == outer && s_holders(outer) == 2u, "a scope holds the shared block");
        }
        CHECK(s_holders(outer) == 1u && atomic_load(&s_frees) == before, "the inner scope drops its hold only");
    }
    CHECK(atomic_load(&s_frees) == before + 1u, "the outer scope releases");
    return 0;
}

static uint8_t s_key[32];

static unsigned s_use_key(bool early)
{
    duct_auto_zero(s_key);
    memset(s_key, 0x5a, sizeof s_key);
    if (early)
        return s_key[1];
    return s_key[0] + s_key[31];
}

static int t_zero(void)
{
    CHECK(s_use_key(false) == 0xb4u, "the return expression reads the secret before the wipe");
    CHECK(s_zero(s_key, sizeof s_key), "duct_auto_zero wipes at the end of the function");
    CHECK(s_use_key(true) == 0x5au, "an early return reads the secret too");
    CHECK(s_zero(s_key, sizeof s_key), "duct_auto_zero wipes on an early return");

    uint8_t buf[16];
    memset(buf, 0xff, sizeof buf);
    duct_secure_zero(buf, sizeof buf);
    CHECK(s_zero(buf, sizeof buf), "duct_secure_zero wipes an array");

    auto heap = duct_new(uint8_t, 16);
    memset(heap, 0xff, 16u);
    duct_secure_zero(heap, 8u);
    CHECK(s_zero(heap, 8u) && duct_at(heap)[8] == 0xffu && duct_at(heap)[15] == 0xffu,
          "duct_secure_zero wipes the bytes named");
    duct_del(heap);

    bool flag = true;
    if (flag)
        duct_secure_zero(buf, 4u);
    else
        flag = false;
    return 0;
}

typedef struct {
    uint8_t a[8],
            b[8];
} pair_t;

static pair_t s_make_pair(void)
{
    return (pair_t){ .a = { 1, 2 }, .b = { 3 } };
}

/* A static variable keeps its bytes after its block closes, so the wipe at the closing brace can be read. */
static int t_decl(void)
{
    uint8_t *array_at = nullptr, *pair_at = nullptr;
    {
        duct_secret_array(static uint8_t, raw, 32, { 1, 2, 3 });
        CHECK(raw[2] == 3u && raw[3] == 0u && raw_zero_.data == raw && raw_zero_.size == 32u,
              "an array takes an initializer and stands for all its bytes");
        memset(raw, 0x5a, sizeof raw);
        array_at = raw;
    }
    CHECK(s_zero(array_at, 32u), "duct_secret_array wipes at the end of its block");
    {
        duct_secret(static pair_t, pair, { .a = { 1, 2 }, .b = { 3 } });
        CHECK(pair.a[1] == 2u && pair.b[0] == 3u && pair_zero_.size == sizeof pair,
              "a struct takes an initializer with designators and commas");
        pair.a[0] = 0xffu;
        pair_at = pair.a;
    }
    CHECK(s_zero(pair_at, sizeof(pair_t)), "duct_secret wipes at the end of its block");

    duct_secret(auto, made, s_make_pair());
    CHECK(made_zero_.data == (uint8_t *)&made && made.a[1] == 2u,
          "auto takes the type of the initializer");
    duct_secret(uint32_t, bare);
    CHECK(bare_zero_.data == (uint8_t *)&bare && bare_zero_.size == sizeof bare,
          "no initializer declares the variable as written");
    return 0;
}

int main(void)
{
    static int (*const tests[])(void) = {
        t_single, t_array, t_typed, t_align, t_place, t_refuse, t_secret, t_share, t_threads, t_del_fn,
        t_auto_del, t_zero, t_decl,
    };
    for (size_t i = 0u; i < sizeof tests / sizeof tests[0]; ++i)
        if (tests[i]())
            return 1;
    printf("alloc: OK\n");
    return 0;
}
