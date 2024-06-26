/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/xxhash.h>

#include "sd.h"

static service_discovery_table *sd_table;
DEFINE_MUTEX(sd_table_mutex);

static void sd_table_lock(void)
{
    mutex_lock(&sd_table_mutex);
}

static void sd_table_unlock(void)
{
    mutex_unlock(&sd_table_mutex);
}

service_discovery_table *service_discovery_table_create()
{
    service_discovery_table *table = kzalloc(sizeof(service_discovery_table), GFP_KERNEL);
    if (!table)
    {
        return ERR_PTR(-ENOMEM);
    }

    hash_init(table->htable);
    return table;
}

int sd_table_init()
{
    sd_table = service_discovery_table_create();
    if (IS_ERR(sd_table))
    {
        return PTR_ERR(sd_table);
    }

    return 0;
}

static u64 sd_entry_hash(const char *name, int len)
{
    return xxh32(name, len, 0);
}

void service_discovery_table_entry_add(service_discovery_table *table, service_discovery_entry *entry)
{
    if (!table || !entry)
    {
        return;
    }

    u64 key = sd_entry_hash(entry->address, strlen(entry->address));

    hash_add(table->htable, &entry->node, key);
}

static service_discovery_entry *sd_table_entry_get_locked(const char *address)
{
    struct service_discovery_entry *entry;

    u64 key = sd_entry_hash(address, strlen(address));

    hash_for_each_possible(sd_table->htable, entry, node, key)
    {
        if (strncmp(entry->address, address, strlen(address)) == 0)
            return entry;
    }

    return NULL;
}

service_discovery_entry *sd_table_entry_get(const char *address)
{
    sd_table_lock();
    service_discovery_entry *entry = sd_table_entry_get_locked(address);
    sd_table_unlock();

    return entry;
}

static void sd_table_entry_del_locked(service_discovery_entry *entry)
{
    if (!entry)
    {
        return;
    }

    pr_debug("remove entry # address[%s]", entry->address);

    hash_del(&entry->node);
}

void sd_table_entry_del(service_discovery_entry *entry)
{
    sd_table_lock();
    sd_table_entry_del_locked(entry);
    sd_table_unlock();
}

void service_discovery_entry_free(service_discovery_entry *entry)
{
    if (!entry)
    {
        return;
    }

    kfree(entry->address);
    size_t i;
    for (i = 0; i < entry->labels_len; i++)
    {
        kfree(entry->labels[i]);
    }
    kfree(entry->labels);
    kfree(entry);
}

static void service_discovery_table_free_locked(service_discovery_table *table)
{
    if (IS_ERR_OR_NULL(table))
        return;

    service_discovery_entry *entry;
    struct hlist_node *tmp;
    int i;
    hash_for_each_safe(table->htable, i, tmp, entry, node)
    {
        pr_debug("delete entry # address[%s]", entry->address);
        sd_table_entry_del_locked(entry);
        service_discovery_entry_free(entry);
    }
    kfree(table);
}

void sd_table_replace(service_discovery_table *table)
{
    sd_table_lock();
    pr_debug("cleanup current sd table entries");
    service_discovery_table_free_locked(sd_table);
    pr_debug("replace sd table");
    sd_table = table;
    sd_table_unlock();
}

void sd_table_free()
{
    sd_table_lock();
    service_discovery_table_free_locked(sd_table);
    sd_table_unlock();
}
