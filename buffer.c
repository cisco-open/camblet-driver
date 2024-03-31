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
#include "buffer.h"

buffer_t *buffer_new(int capacity)
{
    buffer_t *buffer = kmalloc(sizeof(buffer_t), GFP_KERNEL);
    if (!buffer)
        return ERR_PTR(-ENOMEM);
    buffer->data = kmalloc(capacity, GFP_KERNEL);
    if (!buffer->data)
    {
        buffer_free(buffer);
        return ERR_PTR(-ENOMEM);
    }
    buffer->size = 0;
    buffer->capacity = capacity;
    return buffer;
}

void buffer_free(buffer_t *buffer)
{
    if (buffer && !IS_ERR(buffer))
    {
        kfree(buffer->data);
        kfree(buffer);
    }
}

char *buffer_grow(buffer_t *buffer, int len)
{
    int buffer_size = buffer->size;
    int buffer_capacity = buffer->capacity;

    if (buffer_size + len > buffer_capacity)
    {
        int new_capacity = buffer_capacity * 2;
        while (new_capacity < buffer_size + len)
        {
            new_capacity *= 2;
        }

        buffer->data = krealloc(buffer->data, new_capacity, GFP_KERNEL);
        if (!buffer->data)
        {
            return NULL;
        }
        buffer->capacity = new_capacity;
    }

    return buffer->data + buffer_size;
}
