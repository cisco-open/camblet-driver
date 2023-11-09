/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef attest_h
#define attest_h

#include "socket.h"

typedef struct attest_response
{
    struct kref kref;
    char *error;
    char *response;
} attest_response;

typedef struct
{
    char *key;
    attest_response *response;
    struct list_head list;
} attest_response_cache_entry;

void attest_response_get(attest_response *response);
void attest_response_put(attest_response *response);
attest_response *attest_workload(void);

#endif
