/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef device_driver_h
#define device_driver_h

#include <linux/device.h>
#include <linux/fs.h>

#include "runtime.h"
#include "task_context.h"

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

typedef struct command_answer
{
    char *error;
    char *answer;
} command_answer;

void free_command_answer(command_answer *cmd_answer);

command_answer *send_command(char *name, char *data, task_context *context);
wasm_vm_result load_module(char *name, char *code, unsigned length, char *entrypoint);

#define SUCCESS 0
#define DEVICE_NAME "wasm"                 /* Dev name as it appears in /dev/devices   */
#define DEVICE_BUFFER_SIZE 2 * 1024 * 1024 /* Max length of the message from the device */

int chardev_init(void);
void chardev_exit(void);

#endif
