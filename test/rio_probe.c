/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 Duct Software */

/**
 * @file rio_probe.c
 * @brief Unit test for duct_rio.h/duct_rio.c against a real Windows RIO
 * provider.
 * Three checks, each against real production wiring, not a mock:
 * duct_events_rio_available() confirms the linked backend's own ctor
 * already resolved RIO at process start; a real duct_events_init() call
 * confirms that same env's own completion queue was created; the rest
 * repeats the resolve manually and confirms RIOCreateCompletionQueue/
 * RIOCreateRequestQueue actually succeed, not just link — a wrong GUID,
 * IOCTL code, struct layout or calling convention fails here.
 *
 * Exercises the function table only through RIOCreateRequestQueue; the
 * remaining entries have no call of their own here.
 */

#include "duct_rio.h"

#include <stdio.h>

#define CHECK(expr, msg) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s (WSAGetLastError=%d)\n", msg, WSAGetLastError()); return 1; } } while (0)

int main(void)
{
    CHECK(duct_events_rio_available(), "duct_events_rio_available");

    auto env = duct_events_init();
    CHECK(env != nullptr, "duct_events_init");
    CHECK(duct_events_rio_cq_ready(env), "duct_events_rio_cq_ready");
    duct_events_fini(env);

    CHECK(WSAStartup(MAKEWORD(2, 2), &(WSADATA){}) == 0, "WSAStartup");

    SOCKET sock = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                             WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO);
    CHECK(sock != INVALID_SOCKET, "WSASocket with WSA_FLAG_REGISTERED_IO");

    RIO_EXTENSION_FUNCTION_TABLE rio;
    CHECK(duct_rio_load(sock, &rio), "duct_rio_load resolved the extension table");

    RIO_CQ cq = rio.RIOCreateCompletionQueue(2u, nullptr);
    CHECK(cq != nullptr, "RIOCreateCompletionQueue");

    RIO_RQ rq = rio.RIOCreateRequestQueue(sock, 1u, 1u, 1u, 1u, cq, cq, nullptr);
    CHECK(rq != nullptr, "RIOCreateRequestQueue");

    rio.RIOCloseCompletionQueue(cq);
    closesocket(sock);
    WSACleanup();
    printf("rio_probe OK\n");
    return 0;
}
