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
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	const int http_misc_size = 190;
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

	struct stat st;
	if (stat("README.md", &st) < 0)
	{
		perror("could not determine file size");
		goto error;
	}

	typedef enum
	{
		WAITALL_AND_TRUNCATE,
		WAITALL,
		NONE
	} RecvFlags;

	int n = 0;
	RecvFlags flag_state = WAITALL_AND_TRUNCATE;
	int flags = 0;
	while (n != st.st_size + http_misc_size)
	{
		char buf[4096] = {0};
		int recv_size;

		switch (flag_state)
		{
		case WAITALL_AND_TRUNCATE:
			flags = MSG_TRUNC;
			flags |= MSG_WAITALL;
			flag_state = WAITALL;
			break;
		case WAITALL:
			flags = MSG_WAITALL;
			flag_state = NONE;
			break;
		case NONE:
			flags = 0;
			break;
		}

		if ((recv_size = recv(sock, buf, sizeof(buf), flags)) < 0)
		{
			perror("something went wrong during recv");
			goto error;
		}
		n += recv_size;
	}

	close(sock);
	return 0;

error:
	close(sock);
	return 1;
}
