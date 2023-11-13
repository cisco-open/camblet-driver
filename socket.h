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

#include <net/sock.h>
#include <linux/inet.h>

#include "json.h"

int socket_init(void);
void socket_exit(void);

typedef enum
{
    INPUT,
    OUTPUT
} direction;

typedef struct
{
    direction direction;
    char source_ip[INET6_ADDRSTRLEN];
    u16 source_port;
    char destination_ip[INET6_ADDRSTRLEN];
    u16 destination_port;
} net_conn_info;

void add_net_conn_info_to_json(net_conn_info conn_info, JSON_Object *json_object);

#endif
