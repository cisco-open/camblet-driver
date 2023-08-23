/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef context_h
#define context_h

#include <linux/uaccess.h>

#define COMMAND_PATH_BUFLEN 256

char *get_current_proc_path(char *buf, int buflen);

typedef struct task_context
{
    char command_name[TASK_COMM_LEN];
    char *command_path_buffer;
    char *command_path;
    kuid_t uid;
    kgid_t gid;
} task_context;

task_context *get_task_context(void);
void free_task_context(struct task_context *context);

#endif
