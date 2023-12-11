/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef augmentation_h
#define augmentation_h

#include <linux/kref.h>

typedef struct augmentation_response
{
    struct kref kref;
    char *error;
    char *response;
} augmentation_response;

typedef struct
{
    char *key;
    augmentation_response *response;
    struct list_head list;
} augmentation_response_cache_entry;

void augmentation_response_get(augmentation_response *response);
void augmentation_response_put(augmentation_response *response);
augmentation_response *augment_workload(void);

#endif
