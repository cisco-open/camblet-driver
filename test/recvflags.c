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
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
  {
    perror("socket creation failed");
    goto error;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8000);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("connection failed");
    goto error;
  }

  const char *msg = "GET /README.md HTTP/1.1\r\nHost:localhost\r\n\r\n";
  if (send(sock, msg, strlen(msg), 0) < 0)
  {
    perror("could not send message");
    goto error;
  }

  printf("Msg: %s was sent\n", msg);

  int n = 0;
  int i = 0;
  int flags = MSG_TRUNC;
  while (n != 8785)
  {
    char buf[4096] = {0};
    int recv_size;
    if (i == 0)
    {
      flags |= MSG_WAITALL;
    }
    else if (i == 1)
    {
      flags = MSG_WAITALL;
    }
    else
    {
      flags = 0;
    }
    if ((recv_size = recv(sock, buf, sizeof(buf), flags)) < 0)
    {
      perror("something went wrong during recv");
      goto error;
    }
    n += recv_size;
    printf("!!!!!!!!!!!!!!!!!!!!!!%d", n);
    printf("%.*s", n, buf);
    i++;
  }

  printf("\n%d amount of bytes were received\n", n);

  // int i = 0;
  // char buf[4096] = {0};
  // if ((i = recv(sock, buf, sizeof(buf), 0)) < 0)
  // {
  //   perror("something happened during recv");
  //   goto error;
  // }
  // printf("%.*s", i, buf);
  // printf("\n%d amount of bytes were received\n", i);

  close(sock);
  return 0;

error:
  close(sock);
  return 1;
}