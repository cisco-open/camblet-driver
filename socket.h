/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef socket_h
#define socket_h

#include <linux/inet.h>

#include "json.h"

int socket_init(void);
void socket_exit(void);

struct camblet_socket;
typedef struct camblet_socket camblet_socket;

char *get_write_buffer(camblet_socket *s);
// returns a pointer to the buffer where the caller can write len long data (possibly resizing the buffer)
char *get_write_buffer_for_write(camblet_socket *s, int len); 
int get_write_buffer_size(camblet_socket *s);
void set_write_buffer_size(camblet_socket *s, int size);

typedef enum
{
    INPUT,
    OUTPUT
} direction;

typedef struct
{
    u64 id;
    direction direction;
    char source_ip[INET6_ADDRSTRLEN];
    u16 source_port;
    char source_address[INET6_ADDRSTRLEN + 5];
    char destination_ip[INET6_ADDRSTRLEN];
    u16 destination_port;
    char destination_address[INET6_ADDRSTRLEN + 5];
    char *peer_spiffe_id;
} tcp_connection_context;

void add_net_conn_info_to_json(const tcp_connection_context *ctx, JSON_Object *json_object);

#endif
