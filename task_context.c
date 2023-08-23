/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "task_context.h"

task_context *get_task_context(void)
{
    struct task_context *context = kmalloc(sizeof(struct task_context), GFP_KERNEL);

    strcpy(context->command_name, current->comm);
    context->command_path_buffer = kmalloc(COMMAND_PATH_BUFLEN, GFP_KERNEL);
    context->command_path = get_current_proc_path(context->command_path_buffer, COMMAND_PATH_BUFLEN);
    current_uid_gid(&context->uid, &context->gid);

    return context;
}

void free_task_context(struct task_context *context)
{
    if (context->command_path_buffer)
    {
        kfree(context->command_path_buffer);
    }

    kfree(context);
}

char *get_current_proc_path(char *buf, int buflen)
{
    struct file *exe_file;
    char *result = ERR_PTR(-ENOENT);
    struct mm_struct *mm;

    mm = get_task_mm(current);
    if (!mm)
    {
        goto out;
    }
    exe_file = mm->exe_file;
    if (exe_file)
    {
        get_file(exe_file);
        path_get(&exe_file->f_path);
    }
    mmput(mm);
    if (exe_file)
    {
        result = d_path(&exe_file->f_path, buf, buflen);
        path_put(&exe_file->f_path);
        fput(exe_file);
    }

out:
    return result;
}
