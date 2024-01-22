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

int trace_log(const char *message, int log_level, int n, ...);

#define trace_err(message, n, ...) \
    trace_log(message, LOGLEVEL_ERR, n, ##__VA_ARGS__);

#define trace_warn(message, n, ...) \
    trace_log(message, LOGLEVEL_WARNING, n, ##__VA_ARGS__);

#define trace_info(message, n, ...) \
    trace_log(message, LOGLEVEL_INFO, n, ##__VA_ARGS__);

#define trace_debug(message, n, ...) \
    trace_log(message, LOGLEVEL_DEBUG, n, ##__VA_ARGS__);

#define trace_msg(message, n, ...) \
    trace_log(message, -1, n, ##__VA_ARGS__);

#endif
