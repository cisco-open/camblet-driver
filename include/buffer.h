/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef buffer_h
#define buffer_h

typedef struct buffer_t
{
  char *data;
  int size;
  int capacity;
} buffer_t;

/*
 * buffer_new
 *
 * returns a buffer_t struct pointer or ERR_PTR() on error
 */
buffer_t *buffer_new(int capacity);
void buffer_free(buffer_t *buffer);
/*
 * buffer_grow
 *
 * returns a buffer_t struct pointer where the caller can write len long data
 * (possibly resizing the buffer) or NULL on realloc error
 */
char *buffer_grow(buffer_t *buffer, int len);
/*
 * buffer_trim
 *
 * trims the last number of bytes from the buffer if
 * the size of the buffer is greater than the specified amount; otherwise, it resets the buffer.
 */
void buffer_trim(buffer_t *buffer, int amount);

#endif
