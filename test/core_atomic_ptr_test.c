/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file core_atomic_ptr_test.c
 * @brief Compile-time smoke for @c duct_is_atomic_ptr.
 */

#include "duct_core.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

int main(void)
{
    uint64_t na;
    const uint64_t cna = 0;
    volatile uint64_t vna;
    const volatile uint64_t cvna = 0;
    uint64_t _Atomic a;
    const _Atomic uint64_t ca = 0;
    volatile uint64_t _Atomic va;
    const volatile uint64_t _Atomic cva = 0;
    void *_Atomic ap;
    const void *_Atomic cap = 0;
    void *_Atomic vp;
    typedef enum : uint8_t { e_x } my_e;
    _Atomic(my_e) ae;

    CHECK(!duct_is_atomic_ptr(&na), "plain");
    CHECK(!duct_is_atomic_ptr(&cna), "const plain");
    CHECK(!duct_is_atomic_ptr(&vna), "volatile plain");
    CHECK(!duct_is_atomic_ptr(&cvna), "const volatile plain");
    CHECK(duct_is_atomic_ptr(&a), "atomic");
    CHECK(duct_is_atomic_ptr(&ca), "const atomic");
    CHECK(duct_is_atomic_ptr(&va), "volatile atomic");
    CHECK(duct_is_atomic_ptr(&cva), "const volatile atomic");
    CHECK(duct_is_atomic_ptr(&ap), "_Atomic void **");
    CHECK(duct_is_atomic_ptr(&cap), "const _Atomic void *");
    CHECK(duct_is_atomic_ptr(&vp), "void *_Atomic");
    CHECK(duct_is_atomic_ptr(&ae), "enum atomic");

    _Static_assert(duct_is_atomic_ptr(&va), "volatile atomic static");
    _Static_assert(!duct_is_atomic_ptr(&vna), "volatile plain static");

    printf("core_atomic_ptr_test OK\n");
    return 0;
}
