/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */
#include <linux/slab.h>

char *strndup(const char *str, size_t size)
{
    char *dst = kmalloc(size, GFP_KERNEL);
    memcpy(dst, str, size);

    return dst;
}

char *strdup(const char *str)
{
    int len = strlen(str);

    return strndup(str, len);
}
