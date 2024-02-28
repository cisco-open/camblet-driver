/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef http_h
#define http_h

#include <linux/types.h>
#include "buffer.h"
#include "picohttpparser.h"
#include "socket.h"

void inject_header(tcp_connection_context *conn_ctx, buffer_t *buffer, struct phr_header *headers, size_t num_headers, const char *name, const char *value);

#endif
