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
#include "bearssl.h"

#define COMMAND_TIMEOUT_SECONDS 1

typedef struct command_answer
{
    char *error;
    char *answer;
} command_answer;

typedef struct csr_sign_answer
{
    char *error;
    br_x509_certificate *chain;
    size_t chain_len;
    br_x509_trust_anchor *trust_anchors;
    size_t trust_anchors_len;
} csr_sign_answer;

void free_command_answer(command_answer *cmd_answer);

command_answer *send_command(char *name, char *data, task_context *context);

command_answer *send_accept_command(u16 port);
command_answer *send_connect_command(u16 port);
csr_sign_answer *send_csrsign_command(unsigned char *csr);

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
} command;

command *lookup_in_flight_command(char *id);
command *get_command(void);

#endif
