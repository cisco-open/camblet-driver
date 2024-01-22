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

#include <linux/uuid.h>
#include "task_context.h"
#include "bearssl.h"
#include "socket.h"
#include "cert_tools.h"

#define COMMAND_TIMEOUT_SECONDS 1

typedef struct command_answer
{
    char *error;
    char *answer;
} command_answer;

typedef struct csr_sign_answer
{
    char *error;
    x509_certificate *cert;
} csr_sign_answer;

void free_command_answer(command_answer *cmd_answer);

command_answer *send_message(char *name, char *data, task_context *context);
command_answer *send_command(char *name, char *data, task_context *context);
command_answer *answer_with_error(char *error_message);

command_answer *send_augment_command(void);
command_answer *send_accept_command(u16 port);
command_answer *send_connect_command(u16 port);
csr_sign_answer *send_csrsign_command(const unsigned char *csr, const char *ttl);

// create a linked list for outgoing commands
typedef struct command
{
    struct list_head list;
    char *name;
    char *data;
    task_context *context;
    uuid_t uuid;
    struct command_answer *answer;
    bool is_message;
    wait_queue_head_t wait_queue;
} command;

command *lookup_in_flight_command(char *id);
command *get_next_command(void);
void free_command(command *cmd);

#endif
