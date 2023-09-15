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

void *strndup(void *v_dst, const void *v_src, size_t len)
{
    v_dst = kmalloc(len, GFP_KERNEL);
    memcpy(v_dst, v_src, len);

    return v_dst;
}

void *strdup(void *v_dst, const void *v_src)
{
    int len = strlen(v_src);

    return strndup(v_dst, v_src, len);
}
