/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <crypto/hash.h>

static struct shash_desc *init_sdesc(struct crypto_shash *alg)
{
    struct shash_desc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->tfm = alg;
    return sdesc;
}

u8 *hmac_sha256(const u8 *data, unsigned data_len, const char *key, unsigned key_len)
{
    const char *hash_alg_name = "hmac(sha256)";
    struct crypto_shash *shash;
    int err;

    shash = crypto_alloc_shash(hash_alg_name, 0, 0);

    if (IS_ERR(shash))
    {
        printk(KERN_ERR "can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(shash);
    }

    err = crypto_shash_setkey(shash, key, key_len);
    if (err < 0)
    {
        printk(KERN_ERR "can't set key\n");
        crypto_free_shash(shash);
        return ERR_PTR(err);
    }

    struct shash_desc *desc = init_sdesc(shash);

    u8 *out = kmalloc(crypto_shash_digestsize(shash), GFP_KERNEL);

    err = crypto_shash_digest(desc, data, data_len, out);

    if (err < 0)
    {
        printk(KERN_ERR "can't digest\n");
        crypto_free_shash(shash);
        kfree(out);
        kfree(desc);
        return ERR_PTR(err);
    }

    crypto_free_shash(shash);
    kfree(desc);

    return out;
}
