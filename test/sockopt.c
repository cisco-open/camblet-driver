/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

// this is a simple test program that connects to a server and sets and gets a few socket options,
// then connects to a server and sends a http message

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "../include/camblet.h"

int main(int argc, char **argv)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    // setting sockopt "SOL_TCP, TCP_ULP, CAMBLET" should be set before connect
    if (setsockopt(sock, SOL_TCP, TCP_ULP, CAMBLET, sizeof(CAMBLET)) < 0)
    {
        perror("setsockopt");
        return 1;
    }

    char hostname[] = "localhost";
    if (setsockopt(sock, SOL_CAMBLET, CAMBLET_HOSTNAME, hostname, sizeof(hostname)) < 0)
    {
        perror("setsockopt");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8007);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        return 1;
    }

    // Camblet socket options can be read after connect
    camblet_tls_info tls_info;
    socklen_t tls_inf_len = sizeof(tls_info);
    if (getsockopt(sock, SOL_CAMBLET, CAMBLET_TLS_INFO, &tls_info, &tls_inf_len) < 0)
    {
        perror("getsockopt");
        return 1;
    }

    if (tls_info.camblet_enabled != 1)
    {
        perror("TLS not enabled");
        return 1;
    }

    printf("Connected to server with alpn: '%s', Camblet is enabled\n", tls_info.alpn);

    // send a simple http request
    const char *msg = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (send(sock, msg, strlen(msg), 0) < 0)
    {
        perror("send");
        return 1;
    }

    printf("Sent:\n%s\n", msg);

    char buf[8096];
    int n;
    if ((n = recv(sock, buf, sizeof(buf), 0)) < 0)
    {
        perror("recv");
        return 1;
    }

    printf("Received [%d bytes] at first:\n", n);
    printf("%.*s\n", n, buf);

    close(sock);

    return 0;
}
