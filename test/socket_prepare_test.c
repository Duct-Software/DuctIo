/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */
#include "duct.h"
#include "duct_xport.h"
#include <assert.h>
#include <poll.h>

typedef struct { bool allow; unsigned calls; int last; } policy_t;
static bool prepare(void *ctx, int fd, int family)
{
    auto p = (policy_t *)ctx;
    struct sockaddr_storage peer;
    socklen_t length = sizeof peer;
    assert(family == AF_INET);
    /* A UDP connect succeeds immediately, so this detects a hook placed too late. */
    assert(getpeername(fd, (struct sockaddr *)&peer, &length) != 0);
    ++p->calls; p->last = fd;
    return p->allow;
}

int main(void)
{
    for (unsigned udp = 0; udp < 2; ++udp) {
        int peer = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
        assert(peer >= 0);
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        assert(bind(peer, (struct sockaddr *)&addr, sizeof addr) == 0);
        socklen_t length = sizeof addr;
        assert(getsockname(peer, (struct sockaddr *)&addr, &length) == 0);
        if (!udp) assert(listen(peer, 1) == 0);
        policy_t policy = {};
        auto kind = udp ? x_udp_peer : x_tcp;
        duct_sock_t fd = duct_xsocket(AF_INET, kind, 0u, nullptr);
        assert(fd != duct_sock_bad);
        assert(!prepare(&policy, fd, AF_INET) && policy.last == fd);
        close(fd);
        assert(fcntl(policy.last, F_GETFD) == -1);
        struct pollfd wait = {.fd = peer, .events = POLLIN};
        assert(poll(&wait, 1, 20) == 0);
        policy.calls = 0u;
        policy.allow = true;
        fd = duct_xsocket(AF_INET, kind, 0u, nullptr);
        assert(fd != duct_sock_bad && prepare(&policy, fd, AF_INET) && policy.calls == 1u);
        assert(duct_xconnect(kind, fd, (struct sockaddr *)&addr, sizeof addr) == rc_ok);
        if (udp) assert(send(fd, "x", 1, 0) == 1);
        assert(poll(&wait, 1, 1000) == 1);
        if (udp) { char byte; assert(recv(peer, &byte, 1, 0) == 1 && byte == 'x'); }
        else { int accepted = accept(peer, nullptr, nullptr); assert(accepted >= 0); close(accepted); }
        close(fd); close(peer);
    }
    puts("socket_prepare: TCP/UDP protection precedes connect; refusal closes without sending");
    return 0;
}
