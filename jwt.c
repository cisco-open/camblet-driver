/*
 * Copyright (c) 2024 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "base64.h"
#include "crypto.h"
#include "jwt.h"
#include "fastjson/json.h"

#include <linux/slab.h>

jwt_t *jwt_parse(const char *jwt, const unsigned len)
{
    jwt_t *j = kzalloc(sizeof(jwt_t), GFP_KERNEL);
    if (!j)
    {
        return NULL;
    }

    char *header_end = strchr(jwt, '.');

    if (!header_end)
    {
        kfree(j);
        return NULL;
    }

    char *header_json = kzalloc(256, GFP_KERNEL);
    if (!header_json)
    {
        kfree(j);
        return NULL;
    }

    int err = base64_decode(header_json, 256, jwt, header_end - jwt);
    if (err < 0)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    printk(KERN_INFO "header_json: '%s'\n", header_json);

    struct json header = json_parse(header_json);
    if (!json_exists(header))
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    j->alg = json_raw(json_object_get(header, "alg"));
    j->typ = json_raw(json_object_get(header, "typ"));

    char *payload_end = strchr(header_end + 1, '.');
    if (!payload_end)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    char *payload_json = kzalloc(256, GFP_KERNEL);
    if (!payload_json)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    err = base64_decode(payload_json, 256, header_end + 1, payload_end - header_end - 1);
    if (err < 0)
    {
        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        return NULL;
    }

    printk(KERN_INFO "payload_json: '%s'\n", payload_json);

    struct json payload = json_parse(payload_json);
    if (!json_exists(payload))
    {
        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        return NULL;
    }

    j->iss = json_raw(json_object_get(payload, "iss"));
    j->sub = json_raw(json_object_get(payload, "sub"));
    j->aud = json_raw(json_object_get(payload, "aud"));
    j->exp = json_raw(json_object_get(payload, "exp"));

    // signature parsing
    j->signature = payload_end + 1;
    j->signature_len = jwt + len - j->signature;

    j->data = jwt;
    j->data_len = payload_end - jwt;

    //  TODO free all values

    return j;
}

void jwt_free(jwt_t *jwt)
{
    kfree(jwt);
}

int jwt_verify(jwt_t *jwt, const char *secret, const unsigned secret_len)
{
    printk("calculating hash for [%d bytes]: %.*s", jwt->data_len, jwt->data_len, jwt->data);

    char *hash = hmac_sha256(jwt->data, jwt->data_len, secret, strlen(secret));
    if (!hash)
    {
        printk(KERN_ERR "failed to calculate hmac for jwt");

        return -1;
    }

    char signature[32];

    int bytes = base64_decode(signature, sizeof(signature), jwt->signature, jwt->signature_len);
    if (bytes < 0)
    {
        printk(KERN_ERR "failed to base64 encode signature");

        kfree(hash);
        return -1;
    }

    if (bytes != 32)
    {
        printk(KERN_ERR "signature is not 32 bytes");

        kfree(hash);
        return -1;
    }

    int ret = memcmp(hash, signature, bytes);
    
    kfree(hash);

    return ret;
}
