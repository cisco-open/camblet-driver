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
#include "linux/slab.h"
#include "rsa_tools.h"
#include "string.h"

// Define the maximum number of elements inside the cache
#define MAX_CACHE_LENGTH 64

// certs that are in use or used once by a workload
static LIST_HEAD(cert_cache);

// lock for the above list to make it thread safe
static DEFINE_SPINLOCK(cert_cache_lock);
static unsigned long cert_cache_lock_flags;

static size_t linkedlist_length(struct list_head *head) 
{
    struct list_head *pos;
    int length = 0;

    list_for_each(pos, head) {
        length++;
    }

    return length;
}

// add_cert_to_cache adds a certificate chain with a given trust anchor to a linked list. The key will identify this entry.
// the function is thread safe.
void add_cert_to_cache(char *key, br_x509_certificate *chain, size_t chain_len,
                       br_x509_trust_anchor *trust_anchors, size_t trust_anchors_len)
{
    if (!key)
    {
        pr_err("cert_tools: provided key is null");
        return;
    }
    if (linkedlist_length(&cert_cache) >= MAX_CACHE_LENGTH)
    {
        // TODO handle cases when cache lenght is maxed out but no expired certificate
        remove_unused_expired_certs_from_cache();
    }
    cert_with_key *new_entry = kzalloc(sizeof(cert_with_key), GFP_KERNEL);
    if (!new_entry)
    {
        pr_err("cert_tools: memory allocation error");
        return;
    }
    new_entry->key = strdup(key);
    new_entry->chain = chain;
    new_entry->chain_len = chain_len;
    new_entry->trust_anchors = trust_anchors;
    new_entry->trust_anchors_len = trust_anchors_len;

    spin_lock_irqsave(&cert_cache_lock, cert_cache_lock_flags);
    INIT_LIST_HEAD(&new_entry->list);
    list_add(&new_entry->list, &cert_cache);
    spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
}
// remove_unused_expired_certs_from_cache iterates over the whole cache and tries to clean up the unused/expired certificates.
// it works like a garbage collection which now runs before every add.
void remove_unused_expired_certs_from_cache()
{
    cert_with_key *cert_bundle, *cert_bundle_tmp;
    spin_lock_irqsave(&cert_cache_lock, cert_cache_lock_flags);
    list_for_each_entry_safe_reverse(cert_bundle, cert_bundle_tmp, &cert_cache, list)
    {
        if (!validate_cert(cert_bundle->chain))
        {
            spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
            remove_cert_from_cache(cert_bundle);
            spin_lock_irqsave(&cert_cache_lock, cert_cache_lock_flags);
        }
    }
    spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
}

// find_cert_from_cache tries to find a certificate bundle for the given key. In case of failure it returns a NULL.
// the function is thread safe
cert_with_key *find_cert_from_cache(char *key)
{
    cert_with_key *cert_bundle;
    spin_lock_irqsave(&cert_cache_lock, cert_cache_lock_flags);
    list_for_each_entry(cert_bundle, &cert_cache, list)
    {
        if (strncmp(cert_bundle->key, key, strlen(key)) == 0)
        {
            spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
            return cert_bundle;
        }
    }
    spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
    return 0;
}

// remove_cert_from_cache removes a given certificate bundle from the cache
// the function is thread safe
void remove_cert_from_cache(cert_with_key *cert_bundle)
{
    if (cert_bundle)
    {
        spin_lock_irqsave(&cert_cache_lock, cert_cache_lock_flags);
        list_del(&cert_bundle->list);
        kfree(cert_bundle->key);
        free_br_x509_certificate(cert_bundle->chain, cert_bundle->chain_len);
        free_br_x509_trust_anchors(cert_bundle->trust_anchors, cert_bundle->trust_anchors_len);
        kfree(cert_bundle);
        spin_unlock_irqrestore(&cert_cache_lock, cert_cache_lock_flags);
    }
}

// validate_cert validates the given certificate if it has expired or not.
bool validate_cert(br_x509_certificate *cert)
{
    bool result = false;

    br_x509_decoder_context dc;

    br_x509_decoder_init(&dc, 0, 0);
    br_x509_decoder_push(&dc, cert->data, cert->data_len);
    int err = br_x509_decoder_last_error(&dc);
    if (err != 0)
    {
        pr_err("cert_tools: cert decode faild during cert validation %d", err);
        return result;
    }

    // Check if the cert is valid
    uint32_t nbs = dc.notbefore_seconds;
    uint32_t nbd = dc.notbefore_days;
    uint32_t nas = dc.notafter_seconds;
    uint32_t nad = dc.notafter_days;

    time64_t x = ktime_get_real_seconds();
    uint32_t vd = (uint32_t)(x / 86400) + 719528;
    uint32_t vs = (uint32_t)(x % 86400);

    if (vd < nbd || (vd == nbd && vs < nbs))
    {
        pr_warn("cert_tools: cert expired");
    }
    else if (vd > nad || (vd == nad && vs > nas))
    {
        pr_warn("cert_tools: cert not valid yet");
    }
    else
    {
        result = true;
    }

    return result;
}