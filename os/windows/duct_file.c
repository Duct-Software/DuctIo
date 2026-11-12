/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_file.h"

#include <io.h>
#include <windows.h>

duct_file_t *duct_file_open(const char *path, unsigned flags)
{
    bool refuse = duct_has_all(flags, duct_or(duct_file_app, duct_file_mapped));
    duct_do_if(refuse, return nullptr);
    auto f = duct_new(duct_file_t);
    duct_do_if(!f, return nullptr);
    if (duct_has(flags, duct_file_mapped)) {
        f->mode = mapped;
        DWORD access = duct_has(flags, duct_file_out) ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ;
        f->map.handle = CreateFileA(path, access, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f->map.handle == INVALID_HANDLE_VALUE) {
            duct_del(f);
            return nullptr;
        }
        LARGE_INTEGER size;
        if (!GetFileSizeEx(f->map.handle, &size) || size.QuadPart == 0) {
            CloseHandle(f->map.handle);
            duct_del(f);
            return nullptr;
        }
        f->map.size = (size_t)size.QuadPart;
        HANDLE section = CreateFileMappingA(f->map.handle, nullptr,
                                            duct_has(flags, duct_file_out) ? PAGE_READWRITE : PAGE_READONLY,
                                            0u, 0u, nullptr);
        if (!section) {
            CloseHandle(f->map.handle);
            duct_del(f);
            return nullptr;
        }
        f->map.base = (uint8_t *)MapViewOfFile(section, duct_has(flags, duct_file_out) ? FILE_MAP_ALL_ACCESS
                                                                                       : FILE_MAP_READ,
                                               0u, 0u, 0u);
        CloseHandle(section);
        if (!f->map.base) {
            CloseHandle(f->map.handle);
            duct_del(f);
            return nullptr;
        }
        return f;
    }
    /* Append wins over truncate, and out without in writes: the four flag shapes map
     * onto the CRT's own modes, read-write included for a file both read and written. */
    const wchar_t *mode = duct_has(flags, duct_file_app) ? L"ab"
                        : duct_has(flags, duct_file_out) ? ((duct_has(flags, duct_file_in)) ? L"r+b" : L"wb")
                        : duct_has(flags, duct_file_in)  ? L"rb"
                                                         : nullptr;
    if (!mode) {
        duct_del(f);
        return nullptr;
    }
    int wide_n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
    if (wide_n <= 0) {
        duct_del(f);
        return nullptr;
    }
    auto wide = duct_new(wchar_t, (size_t)wide_n);
    if (!wide) {
        duct_del(f);
        return nullptr;
    }
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, duct_at(wide), wide_n);
    f->file = _wfopen(duct_at(wide), mode);
    duct_del(wide);
    if (!f->file) {
        duct_del(f);
        return nullptr;
    }
    f->mode = buffered;
    return f;
}

void duct_file_close(duct_file_t *f)
{
    duct_do_if(!f, return);
    if (f->mode == mapped) {
        duct_discard UnmapViewOfFile(f->map.base);
        CloseHandle(f->map.handle);
    } else {
        fclose(f->file);
    }
    duct_del(f);
}

duct_result_t duct_file_read(duct_file_t *f, void *buf, size_t cap, size_t *n)
{
    if (f->mode == mapped) {
        size_t left = f->map.pos < f->map.size ? f->map.size - f->map.pos : 0u,
               take = cap < left ? cap : left;
        memcpy(buf, f->map.base + f->map.pos, take);
        f->map.pos += take;
        *n = take;
        return rc_ok;
    }
    size_t got = 0u;
    while (got < cap) {
        size_t now = fread((char *)buf + got, 1u, cap - got, f->file);
        got += now;
        if (now == 0u)
            break;
    }
    *n = got;
    return ferror(f->file) ? rc_fatal : rc_ok;
}

duct_result_t duct_file_write(duct_file_t *f, const void *src, size_t len)
{
    if (f->mode == mapped) {
        if (f->map.pos + len > f->map.size)
            return rc_invalid_arg;
        memcpy(f->map.base + f->map.pos, src, len);
        f->map.pos += len;
        return rc_ok;
    }
    size_t put = 0u;
    while (put < len) {
        size_t now = fwrite((const char *)src + put, 1u, len - put, f->file);
        put += now;
        if (now == 0u)
            return rc_fatal;
    }
    return rc_ok;
}

duct_result_t duct_file_flush(duct_file_t *f)
{
    if (f->mode == mapped)
        return FlushViewOfFile(f->map.base, 0u) ? rc_ok : rc_fatal;
    return fflush(f->file) == 0 ? rc_ok : rc_fatal;
}

duct_result_t duct_file_seek(duct_file_t *f, uint64_t off)
{
    if (f->mode == mapped) {
        f->map.pos = (size_t)off;
        return rc_ok;
    }
    return _fseeki64(f->file, (__int64)off, SEEK_SET) == 0 ? rc_ok : rc_fatal;
}

duct_result_t duct_file_tell(const duct_file_t *f, uint64_t *out)
{
    if (f->mode == mapped) {
        *out = f->map.pos;
        return rc_ok;
    }
    __int64 at = _ftelli64(f->file);
    if (at < 0)
        return rc_fatal;
    *out = (uint64_t)at;
    return rc_ok;
}

size_t duct_file_size(const duct_file_t *f)
{
    if (f->mode == mapped)
        return f->map.size;
    LARGE_INTEGER size;
    return GetFileSizeEx((HANDLE)_get_osfhandle(_fileno(f->file)), &size) ? (size_t)size.QuadPart : 0u;
}

duct_view_u8 duct_file_bytes(duct_file_t *f)
{
    return f->mode == mapped ? (duct_view_u8){ f->map.base, f->map.size } : (duct_view_u8){};
}

duct_result_t duct_file_grow([[maybe_unused]] duct_file_t *f, [[maybe_unused]] size_t extra,
                             [[maybe_unused]] duct_view_u8 *tail)
{
    return rc_not_supported;
}

void *duct_file_handle(const duct_file_t *f)
{
    return f->mode == mapped ? f->map.handle
                             : (HANDLE)_get_osfhandle(_fileno(f->file));
}
