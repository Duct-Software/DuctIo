/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

#include "duct_file.h"

#include <stdio.h>
#include <string.h>

#define expect(cond, msg) do { if (!(cond)) return msg; } while (0)

static constexpr char path[] = "ductio_file_test.tmp";
static constexpr char text[] = "hello world!!";

static const char *sc_buffered(void)
{
    auto f = duct_file_open(path, duct_file_out);
    expect(f, "the write open was refused");
    expect(duct_file_write(f, text, 5u) == rc_ok, "the first write was refused");
    uint64_t at = 0u;
    expect(duct_file_tell(f, &at) == rc_ok && at == 5u, "the tell is not at the write's end");
    expect(duct_file_flush(f) == rc_ok, "the flush was refused");
    expect(duct_file_size(f) == 5u, "the size did not follow the writes");
    duct_file_close(f);

    f = duct_file_open(path, duct_file_in);
    expect(f, "the read open was refused");
    char buf[32] = {};
    size_t n = 0u;
    expect(duct_file_read(f, buf, 5u, &n) == rc_ok && n == 5u && memcmp(buf, "hello", 5u) == 0,
           "the capped read did not take the first five bytes");
    expect(duct_file_read(f, buf + 5u, sizeof buf - 5u, &n) == rc_ok && n == 0u,
           "a read past the file's end was not empty");
    expect(duct_file_seek(f, 0u) == rc_ok, "the seek to the start was refused");
    expect(duct_file_read(f, buf, sizeof buf, &n) == rc_ok && n == 5u && memcmp(buf, text, 5u) == 0,
           "the whole read after the seek did not take the file");
    uint64_t end = 0u;
    expect(duct_file_tell(f, &end) == rc_ok && end == 5u, "the tell did not follow the read");
#ifdef _WIN32
    expect(duct_file_handle(f) != nullptr, "the handle accessor answered none");
#else
    expect(duct_file_fd(f) >= 0, "the descriptor accessor answered none");
#endif
    duct_file_close(f);
    return nullptr;
}

static const char *sc_append(void)
{
    auto f = duct_file_open(path, duct_file_app);
    expect(f, "the append open was refused");
    expect(duct_file_write(f, text + 5u, 8u) == rc_ok, "the append write was refused");
    duct_file_close(f);

    f = duct_file_open(path, duct_file_in);
    expect(f, "the read open after the append was refused");
    char buf[32] = {};
    size_t n = 0u;
    expect(duct_file_read(f, buf, sizeof buf, &n) == rc_ok && n == 13u
               && memcmp(buf, text, 13u) == 0,
           "the append truncated the file or wrote elsewhere");
    expect(duct_file_size(f) == 13u, "the size did not follow the append");
    duct_file_close(f);
    return nullptr;
}

static const char *sc_mapped(void)
{
    auto f = duct_file_open(path, duct_file_mapped | duct_file_in | duct_file_out);
    expect(f, "the mapped open was refused");
    expect(duct_file_size(f) == 13u, "the mapped size is not the file's");
    auto view = duct_file_bytes(f);
    expect(view.data && view.size == 13u && memcmp(view.data, text, 13u) == 0,
           "the mapping does not hold the file's bytes");
    expect(duct_file_read(f, view.data, 0u, &(size_t){0}) == rc_ok, "a zero read was refused");
    memcpy(view.data, "HELLO", 5u);
    expect(duct_file_seek(f, 5u) == rc_ok, "the mapped seek was refused");
    uint64_t at = 0u;
    expect(duct_file_tell(f, &at) == rc_ok && at == 5u, "the mapped tell does not follow the seek");
    expect(duct_file_write(f, " wOrLD", 6u) == rc_ok, "the mapped write past the seek was refused");
    expect(duct_file_write(f, "!?x", 3u) == rc_invalid_arg,
           "a mapped write past the file's end is not a caller error");
    expect(duct_file_open(path, duct_file_app | duct_file_mapped) == nullptr,
           "an append open of a mapping was taken, though append into a mapping is the reserved grow");
    expect(duct_file_flush(f) == rc_ok, "the mapped flush was refused");
    expect(duct_file_seek(f, 0u) == rc_ok, "the mapped seek back was refused");
    char buf[32] = {};
    size_t n = 0u;
    expect(duct_file_read(f, buf, sizeof buf, &n) == rc_ok && n == 13u
               && memcmp(buf, "HELLO wOrLD!!", 13u) == 0,
           "the mapped read did not follow the writes");
    duct_file_close(f);

    f = duct_file_open(path, duct_file_mapped | duct_file_in);
    expect(f, "the mapped read-only open was refused");
    view = duct_file_bytes(f);
    expect(view.size == 13u && memcmp(view.data, "HELLO wOrLD!!", 13u) == 0,
           "the read-only mapping does not hold what the write changed");
    duct_file_close(f);
    return nullptr;
}

static const char *sc_reserved(void)
{
    auto f = duct_file_open(path, duct_file_mapped | duct_file_in);
    expect(f, "the mapped open was refused");
    expect(duct_file_grow(f, 8u, &(duct_view_u8){}) == rc_not_supported,
           "the reserved grow did not answer rc_not_supported by name");
    duct_file_close(f);
    f = duct_file_open(path, duct_file_in);
    expect(f, "the buffered open was refused");
    expect(duct_file_grow(f, 8u, nullptr) == rc_not_supported,
           "the reserved grow on a buffered file did not answer rc_not_supported");
    duct_file_close(f);
    return nullptr;
}

static const char *sc_utf8_path(void)
{
#ifdef _WIN32
    static constexpr char utf8_path[] = "ductio_file_test_" "\xD0\xBB\xD0\xBE\xD0\xB3" ".tmp";
    wchar_t wide[128];
    expect(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path, -1, wide, 128) > 0,
           "the UTF-8 path does not convert");
    if (!DeleteFileW(wide))
        expect(GetLastError() == ERROR_FILE_NOT_FOUND, "a stale UTF-8 file cannot be removed");
    auto f = duct_file_open(utf8_path, duct_file_app | duct_file_out);
    expect(f, "the append open of a UTF-8 path was refused");
    expect(duct_file_write(f, text, 5u) == rc_ok, "the write to the UTF-8 path was refused");
    duct_file_close(f);
    f = duct_file_open(utf8_path, duct_file_in);
    expect(f, "the read open of the UTF-8 path was refused");
    char buf[32] = {};
    size_t n = 0u;
    expect(duct_file_read(f, buf, sizeof buf, &n) == rc_ok && n == 5u && memcmp(buf, text, 5u) == 0,
           "the read of the UTF-8 path did not take what the write put there");
    duct_file_close(f);
    expect(DeleteFileW(wide), "the UTF-8 file is not removed");
#endif
    return nullptr;
}

int main(void)
{
    static const struct { const char *name; const char *(*fn)(void); } cases[] = {
        { "buffered",  sc_buffered },
        { "append",    sc_append },
        { "mapped",    sc_mapped },
        { "reserved",  sc_reserved },
        { "utf8_path", sc_utf8_path },
    };
    int failed = 0;
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        const char *err = cases[i].fn();
        printf("file: %-8s %s%s\n", cases[i].name, err ? "FAILED: " : "ok", err ? err : "");
        failed += err != nullptr;
    }
    remove(path);
    return failed ? 1 : 0;
}
