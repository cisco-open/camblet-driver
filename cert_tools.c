/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/list.h>
#include <linux/slab.h>

#include "cert_tools.h"
#include "string.h"
#include "rsa_tools.h"

// Define the maximum number of elements inside the cache
#define MAX_CACHE_LENGTH 64

// certs that are in use or used once by a workload
static LIST_HEAD(cert_cache);

// lock for the above list to make it thread safe
static DEFINE_MUTEX(certificate_cache_lock);

static void cert_cache_lock(void)
{
    mutex_lock(&certificate_cache_lock);
}

static void cert_cache_unlock(void)
{
    mutex_unlock(&certificate_cache_lock);
}

size_t linkedlist_length(struct list_head *head)
{
    struct list_head *pos;
    int length = 0;

    list_for_each(pos, head)
    {
        length++;
    }

    return length;
}

// add_cert_to_cache adds a certificate chain with a given trust anchor to a linked list. The key will identify this entry.
// the function is thread safe.
void add_cert_to_cache(char *key, x509_certificate *cert)
{
    if (!key)
    {
        pr_err("nasp: provided key is null");
        return;
    }

    cert_with_key *new_entry = kzalloc(sizeof(cert_with_key), GFP_KERNEL);
    if (!new_entry)
    {
        pr_err("nasp: memory allocation error");
        return;
    }
    new_entry->key = strdup(key);
    new_entry->cert = cert;

    cert_cache_lock();
    list_add(&new_entry->list, &cert_cache);
    cert_cache_unlock();
}

// remove_unused_expired_certs_from_cache iterates over the whole cache and tries to clean up the unused/expired certificates.
// it works like a garbage collection which now runs before every add.
// TODO handle cases when cache length is maxed out but no expired certificate
void remove_unused_expired_certs_from_cache()
{
    cert_with_key *cert_bundle, *cert_bundle_tmp;

    cert_cache_lock();

    if (linkedlist_length(&cert_cache) >= MAX_CACHE_LENGTH)
    {
        pr_warn("nasp: cache is full removing the oldest element");
        cert_with_key *last_entry = list_last_entry(&cert_cache, cert_with_key, list);
        pr_warn("nasp: removing key:%s from the cache", last_entry->key);
        remove_cert_from_cache_locked(last_entry);
        cert_cache_unlock();
        return;
    }

    list_for_each_entry_safe_reverse(cert_bundle, cert_bundle_tmp, &cert_cache, list)
    {
        if (!validate_cert(cert_bundle->cert->validity))
        {
            remove_cert_from_cache_locked(cert_bundle);
        }
    }
    cert_cache_unlock();
}

// find_cert_from_cache tries to find a certificate bundle for the given key. In case of failure it returns a NULL.
// this function also runs a garbage collection on the cache.
// the function is thread safe
cert_with_key *find_cert_from_cache(char *key)
{
    remove_unused_expired_certs_from_cache();

    cert_with_key *cert_bundle;
    cert_cache_lock();
    list_for_each_entry(cert_bundle, &cert_cache, list)
    {
        if (strcmp(cert_bundle->key, key) == 0)
        {
            x509_certificate_get(cert_bundle->cert);
            cert_cache_unlock();
            return cert_bundle;
        }
    }
    cert_cache_unlock();
    return 0;
}

// remove_cert_from_cache_locked removes a given certificate bundle from the cache
// the function is thread safe
void remove_cert_from_cache(cert_with_key *cert_bundle)
{
    if (cert_bundle)
    {
        cert_cache_lock();
        remove_cert_from_cache_locked(cert_bundle);
        cert_cache_unlock();
    }
}

// remove_cert_from_cache removes a given certificate bundle from the cache
void remove_cert_from_cache_locked(cert_with_key *cert_bundle)
{
    if (cert_bundle)
    {
        list_del(&cert_bundle->list);
        x509_certificate_put(cert_bundle->cert);
        kfree(cert_bundle->key);
        kfree(cert_bundle);
    }
}

// set_cert_validity decodes the provided certificate and filling the validity seconds and days.
// if the decode fails it returns -1
int set_cert_validity(x509_certificate *x509_cert)
{
    br_x509_decoder_context dc;

    br_x509_decoder_init(&dc, 0, 0);
    br_x509_decoder_push(&dc, x509_cert->chain->data, x509_cert->chain->data_len);
    int err = br_x509_decoder_last_error(&dc);
    if (err != 0)
    {
        pr_err("nasp: cert decode faild during setting cert validity: %d", err);
        return -1;
    }
    x509_cert->validity.notbefore_seconds = dc.notbefore_seconds;
    x509_cert->validity.notbefore_days = dc.notbefore_days;

    x509_cert->validity.notafter_seconds = dc.notafter_seconds;
    x509_cert->validity.notafter_days = dc.notafter_days;

    return 0;
}

// validate_cert validates the given certificate if it has expired or not.
bool validate_cert(x509_certificate_validity cert_validity)
{
    bool result = false;

    time64_t x = ktime_get_real_seconds();
    uint32_t vd = (uint32_t)(x / 86400) + 719528;
    uint32_t vs = (uint32_t)(x % 86400);

    if (vd < cert_validity.notbefore_days || (vd == cert_validity.notbefore_days && vs < cert_validity.notbefore_seconds))
    {
        pr_warn("nasp: cert expired");
    }
    else if (vd > cert_validity.notafter_days || (vd == cert_validity.notafter_days && vs > cert_validity.notafter_seconds))
    {
        pr_warn("nasp: cert not valid yet");
    }
    else
    {
        result = true;
    }

    return result;
}

x509_certificate *x509_certificate_init(void)
{
    x509_certificate *cert = kzalloc(sizeof(x509_certificate), GFP_KERNEL);

    kref_init(&cert->kref);

    return cert;
}

static void x509_certificate_free(x509_certificate *cert)
{
    pr_info("nasp: x509_certificate_free");

    if (!cert)
    {
        return;
    }

    free_br_x509_certificate(cert->chain, cert->chain_len);
    free_br_x509_trust_anchors(cert->trust_anchors, cert->trust_anchors_len);

    kfree(cert);
}

static void x509_certificate_release(struct kref *kref)
{
    x509_certificate *cert = container_of(kref, x509_certificate, kref);

    x509_certificate_free(cert);
}

void x509_certificate_get(x509_certificate *cert)
{
    if (!cert)
    {
        return;
    }
    kref_get(&cert->kref);
}

void x509_certificate_put(x509_certificate *cert)
{
    if (!cert)
    {
        return;
    }
    kref_put(&cert->kref, x509_certificate_release);
}
