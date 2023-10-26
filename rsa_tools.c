/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "rsa_tools.h"

#include "linux/kernel.h"
#include "linux/slab.h"

static br_hmac_drbg_context hmac_drbg_ctx;

#define RSA_BIT_LENGHT 2048
#define RSA_PUB_EXP 3

// BearSSL RSA Keygen related functions
// Initialize BearSSL random number generator with a unix getrandom backed seeder
int init_rnd_gen()
{
    br_prng_seeder seeder = br_prng_seeder_system(NULL);

    br_hmac_drbg_init(&hmac_drbg_ctx, &br_sha256_vtable, NULL, 0);
    if (!seeder(&hmac_drbg_ctx.vtable))
    {
        pr_err("rsa_tools: system source of randomness failed");
        return -1;
    }
    return 0;
}

// BearSSL RSA Keygen related functions
// Generates a 2048 bit long rsa key pair
uint32_t generate_rsa_keys(br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub)
{
    br_rsa_keygen rsa_keygen = br_rsa_keygen_get_default();

    unsigned char *raw_priv_key = kmalloc(BR_RSA_KBUF_PRIV_SIZE(RSA_BIT_LENGHT), GFP_KERNEL);
    unsigned char *raw_pub_key = kmalloc(BR_RSA_KBUF_PUB_SIZE(RSA_BIT_LENGHT), GFP_KERNEL);

    return rsa_keygen(&hmac_drbg_ctx.vtable, rsa_priv, raw_priv_key, rsa_pub, raw_pub_key, RSA_BIT_LENGHT, RSA_PUB_EXP);
}

void free_rsa_private_key(br_rsa_private_key *key)
{
    kfree(key->p);
    kfree(key);
}

void free_rsa_public_key(br_rsa_public_key *key)
{
    kfree(key->n);
    kfree(key);
}

void free_br_x509_certificate(br_x509_certificate *chain, size_t chain_len)
{
    if (chain_len > 0)
    {
        size_t i;
        for (i = 0; i < chain_len; i++)
        {
            kfree(chain[i].data);
        }
    }
    kfree(chain);
}

void free_br_x509_trust_anchors(br_x509_trust_anchor *trust_anchors, size_t trust_anchor_len)
{
    if (trust_anchor_len > 0)
    {
        size_t i;
        for (i = 0; i < trust_anchor_len; i++)
        {
            kfree(trust_anchors[i].dn.data);
            kfree(trust_anchors[i].pkey.key.rsa.n);
            kfree(trust_anchors[i].pkey.key.rsa.e);
        }
    }
    kfree(trust_anchors);
}

// BearSSL RSA Keygen related functions
// Encodes rsa private key to pkcs8 der format and returns it's lenght.
// If the der parameter is set to NULL then it computes only the length
int encode_rsa_priv_key_to_der(unsigned char *der, br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub)
{
    br_rsa_compute_privexp rsa_priv_exp_comp = br_rsa_compute_privexp_get_default();
    size_t priv_exponent_size = rsa_priv_exp_comp(NULL, rsa_priv, RSA_PUB_EXP);
    if (priv_exponent_size == 0)
    {
        pr_err("rsa_tools: error happened during priv_exponent lenght calculation");
        return -1;
    }
    unsigned char priv_exponent[priv_exponent_size];
    size_t pexp = rsa_priv_exp_comp(priv_exponent, rsa_priv, RSA_PUB_EXP);
    if (pexp != priv_exponent_size)
    {
        pr_err("rsa_tools: error happened during priv_exponent generation");
        return -1;
    }
    return br_encode_rsa_pkcs8_der(der, rsa_priv, rsa_pub, priv_exponent, priv_exponent_size);
}