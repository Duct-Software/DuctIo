/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

#include "duct_file.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

duct_file_t *duct_file_open(const char *path, unsigned flags)
{
    bool refuse = duct_has_all(flags, duct_or(duct_file_app, duct_file_mapped));
    duct_do_if(refuse, return nullptr);
    auto f = duct_new(duct_file_t);
    duct_do_if(!f, return nullptr);
    if (duct_has(flags, duct_file_mapped)) {
        f->mode = mapped;
        int prot = O_RDONLY;
        if (duct_has(flags, duct_file_out))
            prot = O_RDWR;
        f->map.fd = open(path, prot | O_CLOEXEC);
        if (f->map.fd < 0) {
            duct_del(f);
            return nullptr;
        }
        struct stat st;
        if (fstat(f->map.fd, &st) != 0 || st.st_size == 0) {
            close(f->map.fd);
            duct_del(f);
            return nullptr;
        }
        f->map.size = (size_t)st.st_size;
        f->map.base = mmap(nullptr, f->map.size, prot == O_RDWR ? PROT_READ | PROT_WRITE : PROT_READ,
                           MAP_SHARED, f->map.fd, 0);
        if (f->map.base == MAP_FAILED) {
            close(f->map.fd);
            duct_del(f);
            return nullptr;
        }
        return f;
    }
    /* Append wins over truncate, and out without in writes: the four flag shapes map
     * onto the CRT's own modes, read-write included for a file both read and written. */
    const char *mode = duct_has(flags, duct_file_app) ? "ab"
                     : duct_has(flags, duct_file_out) ? ((duct_has(flags, duct_file_in)) ? "r+b" : "wb")
                     : duct_has(flags, duct_file_in)  ? "rb"
                                                      : nullptr;
    if (!mode) {
        duct_del(f);
        return nullptr;
    }
    f->file = fopen(path, mode);
    if (!f->file) {
        duct_del(f);
        return nullptr;
    }
    duct_discard fcntl(fileno(f->file), F_SETFD, FD_CLOEXEC);
    f->mode = buffered;
    return f;
}

void duct_file_close(duct_file_t *f)
{
    duct_do_if(!f, return);
    if (f->mode == mapped) {
        duct_discard munmap(f->map.base, f->map.size);
        close(f->map.fd);
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
        return msync(f->map.base, f->map.size, MS_SYNC) == 0 ? rc_ok : rc_fatal;
    return fflush(f->file) == 0 ? rc_ok : rc_fatal;
}

duct_result_t duct_file_seek(duct_file_t *f, uint64_t off)
{
    if (f->mode == mapped) {
        f->map.pos = (size_t)off;
        return rc_ok;
    }
    return fseeko(f->file, (off_t)off, SEEK_SET) == 0 ? rc_ok : rc_fatal;
}

duct_result_t duct_file_tell(const duct_file_t *f, uint64_t *out)
{
    if (f->mode == mapped) {
        *out = f->map.pos;
        return rc_ok;
    }
    off_t at = ftello(f->file);
    if (at < 0)
        return rc_fatal;
    *out = (uint64_t)at;
    return rc_ok;
}

size_t duct_file_size(const duct_file_t *f)
{
    if (f->mode == mapped)
        return f->map.size;
    struct stat st;
    return fstat(fileno(f->file), &st) == 0 ? (size_t)st.st_size : 0u;
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

int duct_file_fd(const duct_file_t *f)
{
    return f->mode == mapped ? f->map.fd : fileno(f->file);
}
