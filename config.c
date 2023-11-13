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

#include "config.h"

nasp_config *config;

static DEFINE_MUTEX(nasp_config_mutex_lock);

void nasp_config_lock(void)
{
    mutex_lock(&nasp_config_mutex_lock);
}

void nasp_config_unlock(void)
{
    mutex_unlock(&nasp_config_mutex_lock);
}

void nasp_config_init()
{
    nasp_config_lock();
    config = kzalloc(sizeof(nasp_config), GFP_KERNEL);
    strlcpy(config->trust_domain, "nasp", MAX_TRUST_DOMAIN_LEN);
    nasp_config_unlock();
}

nasp_config *nasp_config_get_locked()
{
    return config;
}

void nasp_config_free()
{
    nasp_config_lock();
    if (!config)
    {
        return;
    }

    kfree(config);
    nasp_config_unlock();
}
