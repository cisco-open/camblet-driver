/*
 * Copyright (c) 2024 Cisco and its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef trace_h
#define trace_h

#include <linux/types.h>
#include "task_context.h"
#include "socket.h"

typedef struct
{
    int pid;
    int uid;
    char command_name[MAX_COMM_LEN];
    struct list_head list;
} trace_request;

int add_trace_request(int pid, int uid, const char *command_name);
void remove_trace_request(trace_request *params);
void clear_trace_requests(void);
trace_request *get_trace_request(int pid, int uid, const char *command_name);
trace_request *get_trace_request_by_partial_match(int pid, int uid, const char *command_name);
char *compose_log_message(const char *message, int n, ...);

int send_trace(const tcp_connection_context *conn_ctx, const char *message, int log_level, int n, ...);

#define trace_log(conn_ctx, message, log_level, n, ...)                     \
    {                                                                       \
        char *log_message = compose_log_message(message, n, ##__VA_ARGS__); \
        if (!IS_ERR(log_message))                                           \
        {                                                                   \
            switch (log_level)                                              \
            {                                                               \
            case LOGLEVEL_ERR:                                              \
                pr_err("%s", log_message);                                  \
                break;                                                      \
            case LOGLEVEL_WARNING:                                          \
                pr_warn("%s", log_message);                                 \
                break;                                                      \
            case LOGLEVEL_INFO:                                             \
                pr_info("%s", log_message);                                 \
                break;                                                      \
            case LOGLEVEL_DEBUG:                                            \
                pr_debug("%s", log_message);                                \
                break;                                                      \
            }                                                               \
            kfree(log_message);                                             \
        }                                                                   \
    }                                                                       \
    send_trace(conn_ctx, message, log_level, n, ##__VA_ARGS__);

#define trace_err(conn_ctx, message, n, ...) \
    trace_log(conn_ctx, message, LOGLEVEL_ERR, n, ##__VA_ARGS__);

#define trace_warn(conn_ctx, message, n, ...) \
    trace_log(conn_ctx, message, LOGLEVEL_WARNING, n, ##__VA_ARGS__);

#define trace_info(conn_ctx, message, n, ...) \
    trace_log(conn_ctx, message, LOGLEVEL_INFO, n, ##__VA_ARGS__);

#define trace_debug(conn_ctx, message, n, ...) \
    trace_log(conn_ctx, message, LOGLEVEL_DEBUG, n, ##__VA_ARGS__);

#define trace_msg(conn_ctx, message, n, ...) \
    send_trace(conn_ctx, message, -1, n, ##__VA_ARGS__);

#endif
