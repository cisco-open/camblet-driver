/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef cert_tools_h
#define cert_tools_h

#include <linux/kref.h>

#include "bearssl.h"

typedef struct
{
    uint32_t notbefore_seconds;
    uint32_t notbefore_days;
    uint32_t notafter_seconds;
    uint32_t notafter_days;
} x509_certificate_validity;

typedef struct
{
    struct kref kref;
    br_x509_certificate *chain;
    size_t chain_len;
    br_x509_trust_anchor *trust_anchors;
    size_t trust_anchors_len;

    x509_certificate_validity validity;
} x509_certificate;

typedef struct
{
    char *key;
    x509_certificate *cert;
    struct list_head list;
} cert_with_key;

/*
 * x509_certificate_init
 *
 * returns an x509_certificate struct pointer or ERR_PTR() on error
 */
x509_certificate *x509_certificate_init(void);
void x509_certificate_get(x509_certificate *cert);
void x509_certificate_put(x509_certificate *cert);

int add_cert_to_cache(char *key, x509_certificate *cert);
cert_with_key *find_cert_from_cache(char *key);
void remove_cert_from_cache(cert_with_key *cert);
void remove_cert_from_cache_locked(cert_with_key *cert);
void remove_unused_expired_certs_from_cache(void);

bool validate_cert(x509_certificate_validity cert_validity);
int set_cert_validity(x509_certificate *x509_cert);

size_t linkedlist_length(struct list_head *head);

#endif