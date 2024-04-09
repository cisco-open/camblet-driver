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

camblet_config *config;

static DEFINE_MUTEX(camblet_config_mutex_lock);

void camblet_config_lock(void)
{
    mutex_lock(&camblet_config_mutex_lock);
}

void camblet_config_unlock(void)
{
    mutex_unlock(&camblet_config_mutex_lock);
}

int camblet_config_init()
{
    camblet_config_lock();
    config = kzalloc(sizeof(camblet_config), GFP_KERNEL);
    if (IS_ERR(config))
    {
        camblet_config_unlock();
        return -ENOMEM;
    }

    strlcpy(config->trust_domain, "camblet", MAX_TRUST_DOMAIN_LEN);
    camblet_config_unlock();

    return 0;
}

camblet_config *camblet_config_get_locked()
{
    return config;
}

void camblet_config_free()
{
    camblet_config_lock();
    kfree(config);
    camblet_config_unlock();
}
