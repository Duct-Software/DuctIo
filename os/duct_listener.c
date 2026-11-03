/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_listener.c
 *  @brief Open listener sockets: resolve the local address, bind, optionally
 *  listen, set non-blocking. Serves TCP accept sockets, UDP shared
 *  classification sockets and AF_UNIX path listeners.
 *
 *  A path listener places a socket file, applies its mode and group before it
 *  listens, and removes the file only while the identity read after the bind
 *  still names it. A path holding a socket nobody serves is unlinked and bound
 *  over; any other occupant refuses the bind.
 */

#include "duct.h"
#include "duct_core.h"
#include "duct_listener.h"
#include "duct_xport.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <afunix.h>
    #include "duct_rio.h"
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <grp.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/udp.h>
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/un.h>
    #include <unistd.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    typedef int sock_len_t;
#else
    typedef socklen_t sock_len_t;
#endif

/** @brief Log one failed socket call to stderr, with the OS error text.
 *  Call before duct_sock_close — closing overwrites the error code.
 */
static void s_bind_err(const char *tag, const char *what, const char *target)
{
    duct_log_err(stderr, duct_sock_err, "%s: %s(%s) failed", tag, what, target);
}

typedef enum {
    bind_tcp_listen,
    bind_udp_plain,
    bind_udp_shared,
} duct_bind_kind_t;

/** @brief Read the local port of bound socket @p fd, 0 where getsockname fails or the family is not IP. */
static uint16_t s_bound_port(duct_sock_t fd)
{
    struct sockaddr_storage ss = {};
    int rc = getsockname(fd, (struct sockaddr *)&ss, &(sock_len_t){ sizeof ss });
    return rc == 0 ? duct_io_peer_from_sockaddr((struct sockaddr *)&ss).port : 0u;
}

/** @brief Replace the port of @p it's address with one no socket holds.
 *  The port is drawn by a plain socket that sets neither SO_REUSEADDR nor SO_REUSEPORT: an ephemeral bind of
 *  a socket that sets both is handed a port another such socket holds, another process's included. The port
 *  stays as it was where the probe socket cannot be opened or bound.
 */
static void s_udp_port_draw(struct addrinfo *it)
{
    duct_sock_t probe = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    duct_do_if(probe == duct_sock_bad, return);
    uint16_t port = bind(probe, it->ai_addr, (sock_len_t)it->ai_addrlen) == 0 ? s_bound_port(probe) : 0u;
    duct_sock_close(probe);
    switch (it->ai_family) {
    case AF_INET:
        ((struct sockaddr_in *)it->ai_addr)->sin_port = htons(port);
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)it->ai_addr)->sin6_port = htons(port);
        break;
    }
}

/** @brief Resolve @p host:*port and bind the first working socket for @p kind,
 *  always non-blocking; an ephemeral bind writes the OS-assigned port back
 *  into *port. The port of an ephemeral datagram bind is one no other socket holds.
 *  Only @c bind_tcp_listen calls listen(). Only @c bind_udp_shared can set
 *  @c WSA_FLAG_REGISTERED_IO on its @c WSASocketW call, and only when the
 *  linked backend's @ref duct_events_dgram_shared_rio_capable also allows it.
 *  @return @c duct_sock_bad on failure.
 */
duct_nonnull(1, 2) static duct_sock_t
s_bind_socket_open(const char *host, uint16_t *port, duct_bind_kind_t kind)
{
    const char *tag = kind == bind_tcp_listen ? "listener_open" : "dgram_socket_open";
    int socktype = kind == bind_tcp_listen ? SOCK_STREAM : SOCK_DGRAM;
    char port_buf[6];
    duct_discard snprintf(port_buf, sizeof(port_buf), "%u", (unsigned)*port);
    char target[256];
    duct_discard snprintf(target, sizeof(target), "%s:%s", host, port_buf);
    struct addrinfo *res = nullptr,
                    hints = {
                        .ai_family = AF_UNSPEC,
                        .ai_socktype = socktype,
                        .ai_flags = AI_PASSIVE | AI_NUMERICSERV,
                    };
    int rc = getaddrinfo(host, port_buf, &hints, &res);
    if (rc != 0 || !res) {
        duct_log(stderr, "%s: getaddrinfo(%s:%u) failed: %s",
                 tag, host, (unsigned)*port, gai_strerror(rc));
        return duct_sock_bad;
    }
    duct_sock_t fd = duct_sock_bad;
    for (auto it = res; it; it = it->ai_next) {
#ifdef _WIN32
        DWORD wsa_flags = WSA_FLAG_OVERLAPPED
                        | (kind == bind_udp_shared && duct_events_dgram_shared_rio_capable()
                           ? WSA_FLAG_REGISTERED_IO : 0u);
        fd = WSASocketW(it->ai_family, it->ai_socktype, it->ai_protocol, nullptr, 0, wsa_flags);
#else
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
#endif
        if (fd == duct_sock_bad) {
            s_bind_err(tag, "socket", target);
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&(int){ 1 }, sizeof(int));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&(int){ 1 }, sizeof(int));
#endif
        if (socktype == SOCK_DGRAM) {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                      (const char *)&(int){ (int)duct_dgram_sock_rcvbuf }, sizeof(int));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                      (const char *)&(int){ (int)duct_dgram_sock_sndbuf }, sizeof(int));
        }
        if (socktype == SOCK_DGRAM && !*port)
            s_udp_port_draw(it);
        rc = bind(fd, it->ai_addr, (sock_len_t)it->ai_addrlen);
        const char *what = "bind";
        if (rc == 0 && kind == bind_tcp_listen) {
            rc = listen(fd, 128);
            what = "listen";
        }
        if (rc != 0) {
            s_bind_err(tag, what, target);
            duct_sock_close(fd);
            fd = duct_sock_bad;
            continue;
        }
        duct_xset_nonblock(fd);
        break;
    }
    /* port 0 = ephemeral: write the OS-assigned port back to *port. */
    if (fd != duct_sock_bad) {
        uint16_t bound = s_bound_port(fd);
        if (bound)
            *port = bound;
    }
    freeaddrinfo(res);
    return fd;
}

/* SO_REUSEPORT on, so duct_listener_route_bind can bind one socket per I/O
 * thread to the same host:port and the kernel spreads accepts across them. */
duct_sock_t duct_listener_open(const char *host, uint16_t *port)
{
    duct_do_if(!host || !*host || !port, return duct_sock_bad);
    return s_bind_socket_open(host, port, bind_tcp_listen);
}

/* SO_REUSEPORT on, so the connected per-peer sockets spun off from this one
 * can bind to the same local address. shared requests WSA_FLAG_REGISTERED_IO
 * where the listener's protocol set includes fl_proto_dgram_shared;
 * s_bind_socket_open makes the actual decision. */
duct_sock_t duct_dgram_socket_open(const char *host, uint16_t *port, bool shared)
{
    duct_do_if(!host || !*host || !port, return duct_sock_bad);
    return s_bind_socket_open(host, port, shared ? bind_udp_shared : bind_udp_plain);
}

/** @brief What a path holds, probed without following a link. */
typedef enum {
    local_absent,  /**< Nothing there. */
    local_socket,  /**< A socket file. */
    local_other,   /**< Anything else, or an entry that cannot be examined. */
} local_kind_t;

/** @brief Bytes of @c sockaddr_un's @c sun_path, the NUL included. */
static constexpr size_t s_local_sun_path_max = sizeof(((struct sockaddr_un *)nullptr)->sun_path);

static_assert(s_local_sun_path_max <= duct_local_path_max,
              "duct_local_bind_t::path has to hold any sun_path");

/** @brief Prefix of every line a path listener's bind logs. */
static const char s_local_tag[] = "listener_open_local";

#ifdef _WIN32

/** @brief Open an overlapped AF_UNIX stream socket. */
static duct_sock_t s_local_socket(void)
{
    return WSASocketW(AF_UNIX, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
}

/** @brief Classify @p path by its own directory entry: a socket is a reparse point tagged AF_UNIX. */
static local_kind_t s_local_kind(const char *path)
{
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA(path, &found);
    if (h == INVALID_HANDLE_VALUE)
        switch (GetLastError()) {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            return local_absent;
        default:
            return local_other;
        }
    FindClose(h);
    bool unix_socket = (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                    && found.dwReserved0 == IO_REPARSE_TAG_AF_UNIX;
    return unix_socket ? local_socket : local_other;
}

/** @brief Read the volume serial and file index of @p path's own entry, following no link.
 *  @return false when the entry cannot be opened or queried. */
static bool s_local_identity(const char *path, uint64_t *dev, uint64_t *ino)
{
    HANDLE h = CreateFileA(path, 0u, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION info;
    bool ok = GetFileInformationByHandle(h, &info);
    CloseHandle(h);
    if (ok) {
        *dev = info.dwVolumeSerialNumber;
        *ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    }
    return ok;
}

/** @brief Delete the file at @p path. */
static bool s_local_remove(const char *path)
{
    return DeleteFileA(path) != 0;
}

/** @brief Test whether a connect to @p path meets anything but a refusal. */
static bool s_local_served(const char *path)
{
    struct sockaddr_storage sa;
    int len = duct_io_sockaddr_from_path(path, &sa);
    SOCKET s = s_local_socket();
    if (s == INVALID_SOCKET)
        return true;
    /* Under IOCP duct_xconnect only binds, the connect being a ConnectEx the events layer posts. */
    duct_xset_nonblock(s);
    int err = connect(s, (const struct sockaddr *)&sa, len) == 0 ? 0 : WSAGetLastError();
    closesocket(s);
    switch (err) {
    case WSAECONNREFUSED:
        return false;
    default:
        return true;
    }
}

/** @brief Mode and group on a socket file: Windows keeps neither. */
static constexpr bool s_local_access_applies = false;

/** @brief Resolve nothing: the bind refuses a group on Windows before this is asked. */
static bool s_local_group([[maybe_unused]] const char *name, [[maybe_unused]] uint32_t *gid)
{
    return true;
}

/** @brief Apply nothing: Windows takes no mode or group. */
static bool s_local_access([[maybe_unused]] const char *path, [[maybe_unused]] uint16_t mode,
                           [[maybe_unused]] uint32_t gid)
{
    return true;
}

#else

/** @brief Mode and group on a socket file: applied through chmod and chown. */
static constexpr bool s_local_access_applies = true;

/** @brief Open an AF_UNIX stream socket that does not survive an exec. */
static duct_sock_t s_local_socket(void)
{
#ifdef SOCK_CLOEXEC
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd != duct_sock_bad)
        duct_xset_fd_flags(fd);
    return fd;
#endif
}

/** @brief Classify @p path by lstat, a symlink counting as @c local_other. */
static local_kind_t s_local_kind(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? local_absent : local_other;
    switch (st.st_mode & S_IFMT) {
    case S_IFSOCK:
        return local_socket;
    default:
        return local_other;
    }
}

/** @brief Read the device and inode of @p path's own entry, following no link.
 *  @return false when lstat fails. */
static bool s_local_identity(const char *path, uint64_t *dev, uint64_t *ino)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return false;
    *dev = (uint64_t)st.st_dev;
    *ino = (uint64_t)st.st_ino;
    return true;
}

/** @brief Unlink @p path. */
static bool s_local_remove(const char *path)
{
    return unlink(path) == 0;
}

/** @brief Test whether a connect to @p path meets anything but a refusal or a missing file. */
static bool s_local_served(const char *path)
{
    struct sockaddr_storage sa;
    int len = duct_io_sockaddr_from_path(path, &sa);
    duct_sock_t fd = duct_xsocket(AF_UNIX, x_local, 0u, nullptr);
    if (fd == duct_sock_bad)
        return true;
    auto rc = duct_xconnect(x_local, fd, (const struct sockaddr *)&sa, (socklen_t)len);
    if (rc == rc_ok)
        close(fd);
    return rc != rc_conn_refused;
}

/** @brief Resolve @p name into @p gid: a decimal gid as written, else a group name.
 *  @return false for a name the group database does not hold or cannot read. */
static bool s_local_group(const char *name, uint32_t *gid)
{
    unsigned number = 0u;
    int used = 0;
    char back[16];
    if (sscanf(name, "%9u%n", &number, &used) == 1 && !name[used]
        && snprintf(back, sizeof back, "%u", number) == used && memcmp(back, name, (size_t)used) == 0) {
        *gid = number;
        return true;
    }
    for (size_t size = 1024u; size <= 65536u; size *= 2u) {
        duct_auto_del auto buf = duct_at(duct_new(char, size));
        if (!buf)
            return false;
        struct group entry, *found = nullptr;
        int err = getgrnam_r(name, &entry, buf, size, &found);
        if (err == 0 && found)
            *gid = (uint32_t)entry.gr_gid;
        if (err != ERANGE)
            return err == 0 && found;
    }
    return false;
}

/** @brief Set the mode of the socket file at @p path to @p mode, following no symlink.
 *  A C library whose fchmodat answers EOPNOTSUPP to AT_SYMLINK_NOFOLLOW, as glibc
 *  before 2.32 does, gets the file opened O_PATH | O_NOFOLLOW, required to be a socket
 *  and changed through /proc/self/fd; a build without O_PATH or a host without /proc fails.
 *  @return false when the mode is not set. */
static bool s_local_chmod(const char *path, mode_t mode)
{
    if (fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW) == 0)
        return true;
#ifdef O_PATH
    if (errno != EOPNOTSUPP)
        return false;
    int fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return false;
    char proc[32];
    duct_discard snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    struct stat st;
    bool set = fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode) && chmod(proc, mode) == 0;
    close(fd);
    return set;
#else
    return false;
#endif
}

/** @brief Set @p path's mode to the low nine bits of @p mode and its group to @p gid, following no symlink.
 *  A @p mode of 0 and a @p gid of UINT32_MAX leave their half alone.
 *  @return false when either call fails. */
static bool s_local_access(const char *path, uint16_t mode, uint32_t gid)
{
    return (!mode || s_local_chmod(path, (mode_t)(mode & 0777u)))
        && (gid == UINT32_MAX || fchownat(AT_FDCWD, path, (uid_t)-1, (gid_t)gid, AT_SYMLINK_NOFOLLOW) == 0);
}

#endif

bool duct_local_path_fits(const char *path)
{
    size_t len = strlen(path);
    return len && len < s_local_sun_path_max;
}

duct_sock_t duct_local_listener_open(const duct_listener_cfg_t *cfg, duct_local_bind_t *local)
{
    const char *path = cfg->local_path;
    assert(duct_local_path_fits(path));
    size_t len = strlen(path);
    if ((cfg->local_mode || cfg->local_group) && !s_local_access_applies) {
        duct_log(stderr, "%s: a mode or a group does not apply on this platform", s_local_tag);
        return duct_sock_bad;
    }
    /* The group is resolved before the path is touched: an unknown one leaves a stale socket in place. */
    uint32_t gid = UINT32_MAX;
    if (cfg->local_group && !s_local_group(cfg->local_group, &gid)) {
        duct_log(stderr, "%s: the group %s is unknown", s_local_tag, cfg->local_group);
        return duct_sock_bad;
    }
    switch (s_local_kind(path)) {
    case local_absent:
        break;
    case local_socket:
        if (s_local_served(path)) {
            duct_log(stderr, "%s: %s is served by another process", s_local_tag, path);
            return duct_sock_bad;
        }
        if (!s_local_remove(path)) {
            s_bind_err(s_local_tag, "remove", path);
            return duct_sock_bad;
        }
        break;
    case local_other:
        duct_log(stderr, "%s: %s exists and is no socket, or cannot be examined", s_local_tag, path);
        return duct_sock_bad;
    }
    duct_sock_t fd = s_local_socket();
    if (fd == duct_sock_bad) {
        s_bind_err(s_local_tag, "socket", path);
        return duct_sock_bad;
    }
    struct sockaddr_storage sa;
    int salen = duct_io_sockaddr_from_path(path, &sa);
    const char *what = "bind";
    bool placed = false;
    /* Listen comes last: no client can queue on the socket before its access is set. */
    if (bind(fd, (const struct sockaddr *)&sa, (sock_len_t)salen) == 0) {
        placed = true;
        what = "access";
        if (s_local_access(path, cfg->local_mode, gid)
            && s_local_identity(path, &local->dev, &local->ino)) {
            what = "listen";
            /* Backlog 0 queues one client on Linux and five on Windows behind a paced listener;
             * a further non-blocking connect fails at once. */
            if (listen(fd, cfg->max_conns_per_s ? 0 : 128) == 0) {
                duct_xset_nonblock(fd);
                memcpy(local->path, path, len + 1u);
                local->cap = cfg->max_sessions;
                local->rate = cfg->max_conns_per_s;
                return fd;
            }
        }
    }
    s_bind_err(s_local_tag, what, path);
    duct_sock_close(fd);
    if (placed)
        duct_discard s_local_remove(path);
    return duct_sock_bad;
}

void duct_local_listener_unlink(duct_local_bind_t *local)
{
    uint64_t dev = 0u,
             ino = 0u;
    if (local->path[0] && s_local_identity(local->path, &dev, &ino)
        && dev == local->dev && ino == local->ino)
        duct_discard s_local_remove(local->path);
    local->path[0] = '\0';
}

/* The unlink runs ahead of the close: on Linux a bound socket keeps its inode
 * allocated, so the identity compared is the placed file's and no newer file's. */
void duct_local_listener_retire(duct_listener_t *listener)
{
    duct_local_listener_unlink(listener->local);
    if (listener->listen_fd != duct_sock_bad) {
        duct_sock_close(listener->listen_fd);
        listener->listen_fd = duct_sock_bad;
    }
}
