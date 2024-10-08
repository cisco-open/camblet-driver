/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef sd_h
#define sd_h

#include <linux/hashtable.h>

typedef struct service_discovery_entry
{
    struct hlist_node node;
    char *address;
    char **labels;
    char labels_len;
} service_discovery_entry;

typedef struct service_discovery_table
{
    DECLARE_HASHTABLE(htable, 8);
} service_discovery_table;

int sd_table_init(void);
void sd_table_free(void);
service_discovery_entry *sd_table_entry_get(const char *address);
void sd_table_replace(service_discovery_table *table);
void sd_table_entry_del(service_discovery_entry *entry);
/*
 * service_discovery_table_create
 *
 * returns a service_discovery_table struct pointer or ERR_PTR() on error
 */
service_discovery_table *service_discovery_table_create(void);
void service_discovery_table_entry_add(service_discovery_table *table, service_discovery_entry *entry);
void service_discovery_entry_free(service_discovery_entry *entry);

#endif
