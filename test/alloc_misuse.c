/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/** @file alloc_misuse.c
 *  @brief Uses of the typed-array macros of @c duct_core.h that the build has to refuse.
 *
 *  Never linked or run. @c CheckAllocMisuse.cmake compiles this file once per @c CASE value with
 *  @c -fsyntax-only: case 0 is the control and has to compile, and every other case holds one
 *  misuse and has to stop the build. A case is a line @c #if CASE == N or @c #elif CASE == N, which
 *  the script reads, so a new case needs no other edit. The hex macros of @c duct_crypto.h take their
 *  size from an array's type, so a pointer given to them is a case.
 */

#include "duct_core.h"
#include "duct_crypto.h"

typedef struct {
    uint64_t a,
             b;
} obj_t;

[[maybe_unused]] static void s_use(void)
{
    [[maybe_unused]] uint32_t local[4];
    [[maybe_unused]] uint8_t key[8] = {};
    [[maybe_unused]] uint8_t *raw = nullptr;
    unsigned n = 4u;
    [[maybe_unused]] uint32_t vla[n];
    [[maybe_unused]] uint32_t *plain = nullptr;
    [[maybe_unused]] uint32_t **twice = nullptr;
    [[maybe_unused]] obj_t *one = nullptr;
    [[maybe_unused]] duct_ptr_t(uint32_t) words = nullptr;
    [[maybe_unused]] duct_ptr_t(const uint32_t) view = nullptr;
    [[maybe_unused]] size_t len;

#if CASE == 0
    /* The control: every use below is the right one. */
    duct_ptr_t(uint32_t) a = duct_new(uint32_t, 4);
    [[maybe_unused]] uint32_t *elements = duct_at(a);
    len = duct_len(a) + duct_byte_len(a);
    one = duct_new(obj_t);
    view = a;
    [[maybe_unused]] const uint32_t *read = duct_at(view);
    duct_del(a);
    duct_del(one);
    [[maybe_unused]] const char *spelled = duct_hex_text(key);
    duct_view_cc digits = { .data = spelled, .size = sizeof key * 2u };
    duct_discard duct_hex_decode(digits, key);
#elif CASE == 1
    /* An array of another element type. */
    [[maybe_unused]] duct_ptr_t(uint8_t) bytes = duct_new(uint32_t, 4);
#elif CASE == 2
    /* The address of a real array for an array of ours. */
    words = &local;
#elif CASE == 3
    /* A plain pointer for an array of ours. */
    words = plain;
#elif CASE == 4
    /* The count of a plain pointer. */
    len = duct_len(plain);
#elif CASE == 5
    /* The count of a pointer to a pointer. */
    len = duct_len(twice);
#elif CASE == 6
    /* The count of the address of a real array. */
    len = duct_len(&local);
#elif CASE == 7
    /* The count of the address of a variable length array. */
    len = duct_len(&vla);
#elif CASE == 8
    /* The elements of an array taken as another element type. */
    [[maybe_unused]] uint8_t *bytes = duct_at(words);
#elif CASE == 9
    /* One object for an array. */
    words = duct_new(uint32_t);
#elif CASE == 10
    /* An array for one object. */
    one = duct_new(obj_t, 4);
#elif CASE == 11
    /* A read-only view handed to a writer. */
    words = view;
#elif CASE == 12
    /* The bytes of a plain pointer. */
    len = duct_byte_len(plain);
#elif CASE == 13
    /* The elements of a plain pointer. */
    plain = duct_at(plain);
#elif CASE == 14
    /* A fourth argument. */
    words = duct_new(uint32_t, 4, 8, 1);
#elif CASE == 15
    /* The text of a plain pointer. */
    [[maybe_unused]] const char *spelled = duct_hex_text(raw);
#elif CASE == 16
    /* Digits decoded into a plain pointer. */
    duct_discard duct_hex_decode((duct_view_cc){}, raw);
#elif CASE == 17
    /* A duct_ptr_t for an element pointer: the whole-owner constructor is the way. */
    [[maybe_unused]] duct_view_u32 bad = duct_view(duct_view_u32, words, 4u);
#elif CASE == 18
    /* A struct pointer for an element pointer. */
    [[maybe_unused]] duct_view_u32 bad = duct_view(duct_view_u32, one, 4u);
#elif CASE == 19
    /* An element type the view does not carry. */
    [[maybe_unused]] uint8_t byte = 0u;
    [[maybe_unused]] duct_view_u32 bad = duct_view(duct_view_u32, &byte, 1u);
#elif CASE == 20
    /* A widen across element types. */
    [[maybe_unused]] duct_view_u32 w = {};
    [[maybe_unused]] duct_view_cu8 bad = duct_view_widen(duct_view_cu8, w);
#elif CASE == 21
    /* A plain pointer for the whole-owner constructor. */
    [[maybe_unused]] duct_view_u32 bad = duct_view_all(duct_view_u32, plain);
#elif CASE == 22
    /* A slice into an element type the view does not carry. */
    [[maybe_unused]] duct_view_u32 w = {};
    [[maybe_unused]] duct_view_u8 bad = duct_view_slice(duct_view_u8, w, 0u, 1u);
#elif CASE == 23
    /* The whole-owner constructor across element types. */
    [[maybe_unused]] duct_ptr_t(uint8_t) bytes = duct_new(uint8_t, 4);
    [[maybe_unused]] duct_view_u32 bad = duct_view_all(duct_view_u32, bytes);
#elif CASE == 24
    /* A widen that keeps the width and swaps the type. */
    DUCT_VIEW_DECLARE(int32_t, misuse_i32)
    [[maybe_unused]] duct_view_u32 w = {};
    [[maybe_unused]] misuse_i32 bad = duct_view_widen(misuse_i32, w);
#else
#error "alloc_misuse.c: no such case"
#endif
}
