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

void inject_header(camblet_socket *s, struct phr_header *headers, size_t num_headers, const char *new_header)
{
	// inject a header after the last one
	size_t new_header_len = strlen(new_header);
	size_t new_buffer_size = get_write_buffer_size(s) + new_header_len;

	// find the new header's position
	char *new_header_pos = headers[num_headers - 1].value + headers[num_headers - 1].value_len + 2;

	// shift the rest of the buffer
	get_write_buffer_for_write(s, new_header_len); // resize the buffer if necessary
	memmove(new_header_pos + new_header_len, new_header_pos, get_write_buffer_size(s) - (new_header_pos - get_write_buffer(s)));

	// inject the new header
	memcpy(new_header_pos, new_header, new_header_len);

	set_write_buffer_size(s, new_buffer_size);

	printk("sendmsg [%s]: after inject headers:\n\"%.*s\"\n", current->comm, get_write_buffer_size(s), get_write_buffer(s));
}
