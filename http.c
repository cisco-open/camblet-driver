/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "http.h"

void inject_header(buffer_t *buffer, struct phr_header *headers, size_t num_headers, const char *name, const char *value)
{
	// check if the header already exists and update it in place if possible
	bool updated = false;
	size_t i;
	for (i = 0; i < num_headers; i++)
	{
		if (headers[i].name_len == strlen(name) && strncasecmp(headers[i].name, name, headers[i].name_len) == 0)
		{
			// if it already exists, update it in place if possible
			size_t new_value_len = strlen(value);
			if (new_value_len <= headers[i].value_len)
			{
				// if the new value fits in the old value's space, just overwrite it
				memcpy(headers[i].value + headers[i].value_len - new_value_len, value, new_value_len);
				memset(headers[i].value, ' ', headers[i].value_len - new_value_len);
			}
			else
			{
				// if the new value doesn't fit, we need to overwrite the old value and shift the rest of the buffer
				size_t shift = new_value_len - headers[i].value_len;
				size_t new_buffer_size = buffer->size + shift;

				// find the old value's position
				const char *old_value_pos = headers[i].value;

				// shift the rest of the buffer
				buffer_grow(buffer, shift); // resize the buffer if necessary
				memmove(old_value_pos + new_value_len, old_value_pos + headers[i].value_len, buffer->size - (old_value_pos + headers[i].value_len - buffer->data));

				// inject the new value
				memcpy(old_value_pos, value, new_value_len);

				buffer->size = new_buffer_size;
			}

			updated = true;
		}
	}

	if (updated)
	{
		goto end;
	}

	// inject a header after the last one
	size_t new_header_len = strlen(name) + 2 + strlen(value) + 2;
	size_t new_buffer_size = buffer->size + new_header_len;

	// find the new header's position
	char *new_header_pos = headers[num_headers - 1].value + headers[num_headers - 1].value_len + 2;

	// shift the rest of the buffer
	buffer_grow(buffer, new_header_len); // resize the buffer if necessary
	memmove(new_header_pos + new_header_len, new_header_pos, buffer->size - (new_header_pos - buffer->data));

	// inject the new header
	snprintf(new_header_pos, new_header_len - 1, "%s: %s", name, value);
	new_header_pos[new_header_len - 2] = '\r';
	new_header_pos[new_header_len - 1] = '\n';

	buffer->size = new_buffer_size;

end:
	pr_debug("inject_header # command[%s] request:\n\"%.*s\"\n", current->comm, buffer->size, buffer->data);
}
