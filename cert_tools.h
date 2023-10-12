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

#include "bearssl.h"
#include "linux/slab.h"

typedef struct
{
	u32 key;
	br_x509_certificate *chain;
    size_t chain_len;
    br_x509_trust_anchor *trust_anchors;
    size_t trust_anchors_len;
    struct list_head list;
} cert_with_key;

void add_cert_to_cache(u16 key, br_x509_certificate *chain, size_t chain_len, 
    br_x509_trust_anchor *trust_anchors, size_t trust_anchors_len);
cert_with_key *find_cert_from_cache(u32 key);
void remove_cert_from_cache(cert_with_key *cert);

#endif