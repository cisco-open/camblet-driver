/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef commands_h
#define commands_h

#include "task_context.h"

#define COMMAND_TIMEOUT_SECONDS 1

typedef struct command_answer
{
    char *error;
    char *answer;
} command_answer;

void free_command_answer(command_answer *cmd_answer);

command_answer *send_command(char *name, char *data, task_context *context);

command_answer *send_accept_command(u16 port);
command_answer *send_connect_command(u16 port);

// create a linked list for outgoing commands
typedef struct command
{
    struct list_head list;
    char *name;
    char *data;
    task_context *context;
    uuid_t uuid;
    struct command_answer *answer;
    wait_queue_head_t wait_queue;
};

// protect the command list with a mutex
static DEFINE_SPINLOCK(command_list_lock);
static unsigned long command_list_lock_flags;
static LIST_HEAD(command_list);
static LIST_HEAD(in_flight_command_list);

#endif
