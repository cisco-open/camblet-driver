/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "cert_tools.h"

#include "linux/list.h"


// certs that are in use or used once by a workload
static LIST_HEAD(cert_list);

//lock for the above list to make it thread safe
static DEFINE_SPINLOCK(cert_list_lock);
static unsigned long cert_list_lock_flags;

void add_cert_to_cache(u16 key, br_x509_certificate *chain, size_t chain_len, 
    br_x509_trust_anchor *trust_anchors, size_t trust_anchors_len)
{
    cert_with_key *new_entry = kzalloc(sizeof(cert_with_key), GFP_KERNEL);
    if (!new_entry)
    {
        pr_err("cert_tools: memory allocation error");
        return;
    }
    new_entry->key = key;
    new_entry->chain = chain;
    new_entry->chain_len = chain_len;
    new_entry->trust_anchors = trust_anchors;
    new_entry->trust_anchors_len  = trust_anchors_len;


    spin_lock_irqsave(&cert_list_lock, cert_list_lock_flags);
    INIT_LIST_HEAD(&new_entry->list);
    list_add(&new_entry->list, &cert_list);
    spin_unlock_irqrestore(&cert_list_lock, cert_list_lock_flags);
}

cert_with_key *find_cert_from_cache(u32 key) 
{
    cert_with_key *cert_bundle;
    spin_lock_irqsave(&cert_list_lock, cert_list_lock_flags);
    list_for_each_entry(cert_bundle, &cert_list, list)
    {
        if (cert_bundle->key == key)
        {   
            spin_unlock_irqrestore(&cert_list_lock, cert_list_lock_flags);
            return cert_bundle;
        }
    }
    spin_unlock_irqrestore(&cert_list_lock, cert_list_lock_flags);
    return 0;
}

void remove_cert_from_cache(cert_with_key *cert_bundle)
{
    if (cert_bundle)
    {
        spin_lock_irqsave(&cert_list_lock, cert_list_lock_flags);
        list_del(&cert_bundle->list);
        kfree(cert_bundle->chain);
        kfree(cert_bundle->trust_anchors);
        kfree(cert_bundle);
        spin_unlock_irqrestore(&cert_list_lock, cert_list_lock_flags);
    }
}