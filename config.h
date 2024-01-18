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

typedef struct camblet_config
{
    char trust_domain[MAX_TRUST_DOMAIN_LEN];
} camblet_config;

camblet_config *camblet_config_get_locked(void);
void camblet_config_lock(void);
void camblet_config_unlock(void);
void camblet_config_init(void);
void camblet_config_free(void);

#endif
