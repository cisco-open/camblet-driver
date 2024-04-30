/*
 * Copyright (c) 2024 Cisco and its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/list.h>
#include <linux/slab.h>
#include "trace.h"
#include "task_context.h"
#include "json.h"
#include "commands.h"
#include "socket.h"
#include "string.h"

// a list to hold trace requests
static LIST_HEAD(trace_requests);

// lock for the above list to make it thread safe
static DEFINE_MUTEX(trace_requests_lock);

static void lock_trace_requests(void)
{
    mutex_lock(&trace_requests_lock);
}

static void unlock_trace_requests(void)
{
    mutex_unlock(&trace_requests_lock);
}

int add_trace_request(int pid, int uid, const char *command_name)
{
    trace_request *tr = kzalloc(sizeof(trace_request), GFP_KERNEL);

    if (!tr)
    {
        return -ENOMEM;
    }

    tr->pid = pid;
    tr->uid = uid;
    if (command_name)
    {
        strncpy(tr->command_name, command_name, MAX_COMM_LEN);
    }

    lock_trace_requests();
    list_add(&tr->list, &trace_requests);
    unlock_trace_requests();

    return 0;
}

trace_request *get_trace_request(int pid, int uid, const char *command_name)
{
    trace_request *tr;

    lock_trace_requests();

    pr_debug("look for pid[%d] uid[%d] command_name[%s]", pid, uid, command_name);

    list_for_each_entry(tr, &trace_requests, list)
    {
        pr_debug("check pid[%d] uid[%d] command_name[%s]", tr->pid, tr->uid, tr->command_name);

        if ((tr->pid > 0 || pid > 0) && tr->pid != pid)
        {
            continue;
        }

        if ((tr->uid >= 0 || uid > 0) && tr->uid != uid)
        {
            continue;
        }

        if ((strlen(tr->command_name) > 0 || command_name) && strcmp(command_name, tr->command_name))
        {
            continue;
        }

        unlock_trace_requests();

        return tr;
    }

    unlock_trace_requests();

    return 0;
}

trace_request *get_trace_request_by_partial_match(int pid, int uid, const char *command_name)
{
    trace_request *tr;

    if (list_empty(&trace_requests))
    {
        return NULL;
    }

    lock_trace_requests();

    pr_debug("look for trace request # pid[%d] uid[%d] command_name[%s]", pid, uid, command_name);

    list_for_each_entry(tr, &trace_requests, list)
    {
        pr_debug("check trace request # pid[%d] uid[%d] command_name[%s]", tr->pid, tr->uid, tr->command_name);

        if (tr->pid > 0 && tr->pid != pid)
        {
            continue;
        }

        if (tr->uid > 0 && tr->uid != uid)
        {
            continue;
        }

        if (strlen(tr->command_name) > 0 && strcmp(command_name, tr->command_name))
        {
            continue;
        }

        unlock_trace_requests();

        pr_debug("check trace request match found # pid[%d] uid[%d] command_name[%s]", tr->pid, tr->uid, tr->command_name);

        return tr;
    }

    unlock_trace_requests();

    pr_debug("check trace request match not found # pid[%d] uid[%d] command_name[%s]", tr->pid, tr->uid, tr->command_name);

    return NULL;
}

static void free_trace_request(trace_request *tr)
{
    if (tr)
    {
        list_del(&tr->list);
        kfree(tr);
    }
}

void remove_trace_request(trace_request *tr)
{
    if (tr)
    {
        lock_trace_requests();
        free_trace_request(tr);
        unlock_trace_requests();
    }
}

void clear_trace_requests()
{
    trace_request *tr, *tmp;

    lock_trace_requests();

    list_for_each_entry_safe(tr, tmp, &trace_requests, list)
    {
        free_trace_request(tr);
    }

    unlock_trace_requests();
}

char *compose_log_message(const char *message, int n, va_list args)
{
    int i;
    va_list args_copy;
    char *retval = NULL;

    va_copy(args_copy, args);

    if (message == NULL || n < 0 || (n > 0 && n % 2 != 0))
    {
        retval = ERR_PTR(-EINVAL);

        goto out;
    }

    int size = strlen(message);
    if (n > 0)
        size += 3; // for the separator

    for (i = 0; i < n; i += 2)
    {
        const char *var = va_arg(args, const char *);
        const char *value = va_arg(args, const char *);

        if (!var)
        {
            retval = ERR_PTR(-EINVAL);
            goto out;
        }

        if (var && value)
        {
            size += strlen(var) + strlen(value) + 2; // +2 for []
            if (i < n - 2)
                size += 1; // +1 for a space
        }
    }

    char *log_message = kzalloc(size + 1, GFP_KERNEL);
    if (log_message == NULL)
    {
        retval = ERR_PTR(-ENOMEM);

        goto out;
    }

    sprintf(log_message, "%s", message);

    bool sep = false;

    for (i = 0; i < n; i += 2)
    {
        const char *var = va_arg(args_copy, const char *);
        const char *value = va_arg(args_copy, const char *);
        if (var && value)
        {
            if (!sep)
            {
                strcat(log_message, " # ");
                sep = true;
            }
            sprintf(log_message + strlen(log_message), "%s[%s]", var, value);
            if (i < n - 2)
            {
                strcat(log_message, " ");
            }
        }
    }

    retval = log_message;

out:
    va_end(args_copy);

    return retval;
}

int trace_log(const tcp_connection_context *conn_ctx, const char *message, int log_level, int n, ...)
{
    int ret = 0;
    unsigned int i;
    va_list args, args_copy;
    char *level = NULL;

    task_context *task_ctx = get_task_context();
    if (IS_ERR(task_ctx))
        return PTR_ERR(task_ctx);

    if (n < 0 || (n > 0 && n % 2 != 0))
    {
        return -EINVAL;
    }

    if (log_level > 0)
    {
        va_start(args, n);
        va_copy(args_copy, args);
        char *log_message = compose_log_message(message, n, args_copy);
        if (IS_ERR(log_message))
            return PTR_ERR(log_message);

        switch (log_level)
        {
        case LOGLEVEL_ERR:
            pr_err("%s", log_message);
            level = "error";
            break;
        case LOGLEVEL_WARNING:
            pr_warn("%s", log_message);
            level = "warning";
            break;
        case LOGLEVEL_INFO:
            pr_info("%s", log_message);
            level = "info";
            break;
        case LOGLEVEL_DEBUG:
            pr_debug("%s", log_message);
            level = "debug";
            break;
        default:
            printk("%s", log_message);
        }

        kfree(log_message);
        va_end(args_copy);
        va_end(args);
    }

    trace_request *tr = get_trace_request_by_partial_match(task_ctx->pid, task_ctx->uid.val, task_ctx->command_name);
    if (!tr)
    {
        free_task_context(task_ctx);
        return ret;
    }

    JSON_Value *root_value = json_value_init_object();
    if (!root_value)
    {
        free_task_context(task_ctx);
        return -ENOMEM;
    }

    JSON_Object *root_object = json_value_get_object(root_value);

    if (json_object_set_string(root_object, "message", message) < 0)
    {
        ret = -ENOMEM;
        goto out;
    }

    if (log_level > 0 && json_object_set_string(root_object, "level", level) < 0)
    {
        ret = -ENOMEM;
        goto out;
    }

    if (conn_ctx)
    {
        const char *id_str = strprintf("%llu", conn_ctx->id);
        if (IS_ERR(id_str))
        {
            ret = PTR_ERR(id_str);
            goto out;
        }
        int retval = json_object_set_string(root_object, "correlation_id", id_str);
        kfree(id_str);
        if (retval < 0)
        {
            ret = -ENOMEM;
            goto out;
        }
    }

    va_start(args, n);
    for (i = 0; i < n; i += 2)
    {
        const char *var = va_arg(args, const char *);
        const char *value = va_arg(args, const char *);
        if (var && value && json_object_set_string(root_object, var, value) < 0)
        {
            pr_err("could not set json string [%s] [%s]", var, value);
        }
    }
    va_end(args);

    send_message("log", json_serialize_to_string(root_value), task_ctx);
    json_value_free(root_value);

    return ret;

out:
    json_value_free(root_value);
    free_task_context(task_ctx);

    return ret;
}
