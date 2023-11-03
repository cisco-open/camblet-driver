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

#include "wasm.h"

wasm_vm_result load_module(const char *name, const char *code, unsigned length, const char *entrypoint);

#define SUCCESS 0
#define DEVICE_NAME "nasp"                 /* Dev name as it appears in /dev/devices   */
#define DEVICE_BUFFER_SIZE 2 * 1024 * 1024 /* Max length of the message from the device */

enum
{
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

extern atomic_t already_open;

int chardev_init(void);
void chardev_exit(void);

#endif
