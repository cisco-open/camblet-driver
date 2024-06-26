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
#include <linux/sched/mm.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 64

struct namespace_ids
{
    unsigned int uts;
    unsigned int ipc;
    unsigned int mnt;
    unsigned int pid;
    unsigned int net;
    unsigned int time;
    unsigned int cgroup;
};

typedef struct task_context
{
    char command_name[MAX_COMM_LEN];
    char command_path_buffer[MAX_PATH_LEN];
    char *command_path;
    kuid_t uid;
    kgid_t gid;
    pid_t pid;
    struct namespace_ids namespace_ids;
    char cgroup_path[MAX_PATH_LEN];
} task_context;

/*
 * get_task_context
 *
 * returns a task_context struct pointer or ERR_PTR() on error
 */
task_context *get_task_context(void);
void free_task_context(struct task_context *context);

#endif
