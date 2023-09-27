/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef rsa_tools_h
#define rsa_tools_h

#include "bearssl.h"

int init_rnd_gen(void);
uint32_t generate_rsa_keys(br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub);
void free_rsa_private_key(br_rsa_private_key *key);
void free_rsa_public_key(br_rsa_public_key *key);
int encode_rsa_priv_key_to_der(unsigned char *der, br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub);

#endif
