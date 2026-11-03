/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_file.h
 *  @brief The one file module of the engine: buffered and mapped access to a whole file,
 *  the mode chosen at open and held for the handle's life.
 *
 *  Buffered access is @c FILE-backed on every platform and reads capped or whole, writes
 *  and appends; it is the mode of the configuration and deny files, the key store and the
 *  logs. Mapped access anchors a read or read-write mapping over a pre-sized, non-empty
 *  file, whose bytes @c duct_file_bytes hands out whole; extension and append into a
 *  mapping are reserved and answer @c rc_not_supported.
 *  A caller needing both modes opens twice: past the descriptor they share nothing.
 *
 *  The descriptor accessors exist for events about files alone, a watched file's fd
 *  and a directory's overlapped handle; regular files never ride a reactor, whose poll
 *  reports one always ready. Data I/O through the descriptor is not on offer.
 */

#ifndef DUCT_FILE_H
#define DUCT_FILE_H

#include "duct_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The access mode of one duct_file, fixed at the open. */
typedef enum : uint8_t {
    buffered, /**< The CRT's FILE *: read, write, seek, tell, flush. */
    mapped,   /**< The whole-file view: memcpy in bounds, msync. */
} duct_file_mode_t;

/** @brief One open file: the mode and that mode's own state, nothing shared past the
 *  descriptor — the buffered mode lives entirely in the @c FILE *, the mapped one in
 *  the anchor, the view and its position.
 */
typedef struct duct_file {
    duct_file_mode_t mode; /**< The mode, fixed at the open. */
    union {
        FILE *file; /**< Buffered: the CRT handle, whose own cursor the calls ride. */
#ifdef _WIN32
        struct { HANDLE handle; uint8_t *base; size_t size, pos; } map; /**< Mapped: the file's handle, the view and its position. */
#else
        struct { int fd; uint8_t *base; size_t size, pos; } map; /**< Mapped: the file's descriptor, the view and its position. */
#endif
    };
} duct_file_t;

/** @brief Flags of @c duct_file_open; one access mode and its direction. */
enum : unsigned {
    duct_file_in     = 1u << 0, /**< Read. */
    duct_file_out    = 1u << 1, /**< Write: create or truncate, unless @c duct_file_app stands with it. */
    duct_file_app    = 1u << 2, /**< Write to the end, never truncate. */
    duct_file_mapped = 1u << 3, /**< Memory-mapped access mode. */
};

/** @brief Open the file at @p path in the mode the flags name.
 *  Buffered: @c in reads, @c out creates or truncates, @c app appends, and @c out with
 *  @c in reads and writes in place. Mapped: the file must exist, be non-empty, and the
 *  mapping writes where @c out stands with it and reads otherwise; the size is settled
 *  at the open. An open naming @c app with @c mapped refuses: append into a mapping is
 *  the reserved grow path and nothing else.
 *  @return the handle, nullptr when the OS refuses the file or the mapping, or the flags
 *          name the refused combination.
 */
duct_file_t *duct_file_open(const char *path, unsigned flags);

/** @brief Flush and unmap or close @p f, and free the handle. A null @p f does nothing. */
void duct_file_close(duct_file_t *f);

/** @brief Read up to @p cap bytes of @p f into @p buf, whole or to the end of the file.
 *  A mapped handle copies from the mapping at its position, a buffered one reads until
 *  the cap or the end, whichever is first.
 *  @return @c rc_ok with the byte count in @p n, 0 at the end of the file; @c rc_fatal
 *          when a read error met the call.
 */
duct_nonnull(1, 2, 4) duct_result_t duct_file_read (duct_file_t *f, void *buf, size_t cap, size_t *n);

/** @brief Write @p len bytes of @p src to @p f at its position.
 *  A mapped handle answers @c rc_invalid_arg for a write past the file's size — the bound
 *  is the caller's to respect, the mapping does not extend.
 *  @return @c rc_ok; @c rc_invalid_arg when a mapped write has no room; @c rc_fatal when
 *          the OS refused a buffered write.
 */
duct_nonnull(1, 2) duct_result_t duct_file_write(duct_file_t *f, const void *src, size_t len);

/** @brief Push the buffered bytes of @p f to the file, and a mapping's dirty pages to their backing storage.
 *  @return @c rc_ok, or @c rc_fatal when the OS refuses.
 */
duct_nonnull(1) duct_result_t duct_file_flush(duct_file_t *f);

/** @brief Set the position of @p f to @p off bytes from the start, the one seek the module takes.
 *  @return @c rc_ok, or @c rc_fatal when the OS refuses.
 */
duct_nonnull(1) duct_result_t duct_file_seek (duct_file_t *f, uint64_t off);

/** @brief Read the position of @p f into @p out, bytes from the start.
 *  @return @c rc_ok, or @c rc_fatal when the OS refuses.
 */
duct_nonnull(1, 2) duct_result_t duct_file_tell (const duct_file_t *f, uint64_t *out);

/** @brief Size of the file of @p f, bytes; 0 when the OS refuses the query. */
duct_nonnull(1) size_t        duct_file_size (const duct_file_t *f);

/** @brief The mapping of @p f whole: its base and size, an empty view for a buffered handle. */
duct_nonnull(1) duct_view_u8  duct_file_bytes(duct_file_t *f);

/** @brief Extend @p f by @p extra bytes and give the fresh space as @p tail.
 *  Reserved for the owner's extend technique, which fills it without a signature change.
 *  @return @c rc_not_supported.
 */
duct_nonnull(1) duct_result_t duct_file_grow (duct_file_t *f, size_t extra, duct_view_u8 *tail);
#ifdef _WIN32
/** @brief The Windows handle of @p f, for watching a file or a directory for changes. Never for data I/O. */
duct_nonnull(1) void *duct_file_handle(const duct_file_t *f);
#else
/** @brief The descriptor of @p f, for watching a file for changes. Never for data I/O. */
duct_nonnull(1) int   duct_file_fd(const duct_file_t *f);
#endif

#ifdef __cplusplus
}
#endif

#endif
