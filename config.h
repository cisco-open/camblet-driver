/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef config_h
#define config_h

#define MAX_TRUST_DOMAIN_LEN 256

typedef struct nasp_config
{
    char *trust_domain;
} nasp_config;

nasp_config *nasp_config_get_locked(void);
void nasp_config_lock(void);
void nasp_config_unlock(void);
void nasp_config_init(void);
void nasp_config_free(void);

#endif
