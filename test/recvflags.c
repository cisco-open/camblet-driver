/*
  * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
  *
  * SPDX-License-Identifier: MIT OR GPL-2.0-only
  *
  * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
  * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
  * modified, or distributed except according to those terms.
  */

 // This is a simple test program which connects to a server and sends various data with different flags.

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>

 int main(int argc, char *argv[])
 {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
      perror("socket creation failed");
      goto error;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8000);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
      perror("connection failed");
      goto error;
    }

    const char *msg = "GET / HTTP/1.1\r\nHost:localhost\r\n\r\n";
    if(send(sock, msg, strlen(msg), 0) < 0)
    {
      perror("could not send message");
      goto error;
    }

    printf("Msg: %s was sent\n", msg);

    char buf[8096];
    int n;
    if((n = recv(sock, buf, sizeof(buf), MSG_TRUNC)) < 0)
    {
      perror("cound not recv message");
      goto error;
    }

    printf("%d amount of bytes were received\n", n);
    printf("%.*s\n", n, buf);

    close(sock);
    return 0;
    
    error:
    close(sock);
    return 1;
 }