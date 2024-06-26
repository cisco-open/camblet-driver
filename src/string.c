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

char *strprintf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    int len = vsnprintf(NULL, 0, fmt, args) + 1;
    va_end(args);

    char *dst = kzalloc(len, GFP_KERNEL);
    if (!dst)
        return ERR_PTR(-ENOMEM);

    va_start(args, fmt);
    vsnprintf(dst, len, fmt, args);
    va_end(args);

    return dst;
}
