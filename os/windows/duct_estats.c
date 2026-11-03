/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Duct Software, author: Constantin Papizh */

/** @file duct_estats.c
 *  @brief A TCP socket's unsent bytes off the stack's per-connection statistics:
 *  ESTATS @c CurAppWQueue of @c TcpConnectionEstatsSendBuff, by the connection's
 *  row.
 *
 *  Collection is the connection's. Every reading checks @c EnableCollection in the
 *  read-write part of the statistics and, finding it off, turns it on and answers
 *  unread; a process the stack refuses never gets past that.
 */

#include "duct_xport.h"

#include <iphlpapi.h>

uint64_t duct_xget_tx_unsent(SOCKET fd)
{
    struct sockaddr_storage local, remote;
    int local_len = sizeof local,
        remote_len = sizeof remote;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0
        || getpeername(fd, (struct sockaddr *)&remote, &remote_len) != 0
        || local.ss_family != remote.ss_family)
        return duct_tx_unsent_unread;
    TCP_ESTATS_SEND_BUFF_RW_v0 rw = {};
    TCP_ESTATS_SEND_BUFF_ROD_v0 rod = {};
    ULONG rc = ERROR_NOT_SUPPORTED;
    if (local.ss_family == AF_INET) {
        auto l = (const struct sockaddr_in *)&local;
        auto r = (const struct sockaddr_in *)&remote;
        MIB_TCPROW row = { .dwState = MIB_TCP_STATE_ESTAB,
                           .dwLocalAddr = l->sin_addr.s_addr, .dwLocalPort = l->sin_port,
                           .dwRemoteAddr = r->sin_addr.s_addr, .dwRemotePort = r->sin_port };
        rc = GetPerTcpConnectionEStats(&row, TcpConnectionEstatsSendBuff, (PUCHAR)&rw, 0,
                                       sizeof rw, nullptr, 0, 0, (PUCHAR)&rod, 0, sizeof rod);
        if (rc == NO_ERROR && !rw.EnableCollection) {
            rw.EnableCollection = TRUE;
            duct_discard SetPerTcpConnectionEStats(&row, TcpConnectionEstatsSendBuff, (PUCHAR)&rw,
                                                   0, sizeof rw, 0);
            return duct_tx_unsent_unread;
        }
    } else if (local.ss_family == AF_INET6) {
        auto l = (const struct sockaddr_in6 *)&local;
        auto r = (const struct sockaddr_in6 *)&remote;
        MIB_TCP6ROW row = { .State = MIB_TCP_STATE_ESTAB,
                            .LocalAddr = l->sin6_addr, .dwLocalScopeId = l->sin6_scope_id,
                            .dwLocalPort = l->sin6_port,
                            .RemoteAddr = r->sin6_addr, .dwRemoteScopeId = r->sin6_scope_id,
                            .dwRemotePort = r->sin6_port };
        rc = GetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsSendBuff, (PUCHAR)&rw, 0,
                                        sizeof rw, nullptr, 0, 0, (PUCHAR)&rod, 0, sizeof rod);
        if (rc == NO_ERROR && !rw.EnableCollection) {
            rw.EnableCollection = TRUE;
            duct_discard SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsSendBuff, (PUCHAR)&rw,
                                                    0, sizeof rw, 0);
            return duct_tx_unsent_unread;
        }
    }
    return rc == NO_ERROR ? rod.CurAppWQueue : duct_tx_unsent_unread;
}
