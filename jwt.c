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
#include "json.h"
#include <linux/slab.h>

jwt_t *jwt_parse(const char *jwt, const char *secret)
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

    JSON_Value *header = json_parse_string(header_json);
    if (!header)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    JSON_Object *header_obj = json_value_get_object(header);

    j->alg = json_object_get_string(header_obj, "alg");
    j->typ = json_object_get_string(header_obj, "typ");

    char *payload_end = strchr(header_end + 1, '.');
    if (!payload_end)
    {
        kfree(j);
        kfree(header_json);
        json_value_free(header);
        return NULL;
    }

    char *payload_json = kzalloc(256, GFP_KERNEL);
    if (!payload_json)
    {
        kfree(j);
        kfree(header_json);
        json_value_free(header);
        return NULL;
    }

    err = base64_decode(payload_json, 256, header_end + 1, payload_end - header_end - 1);
    if (err < 0)
    {
        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        json_value_free(header);
        return NULL;
    }

    printk(KERN_INFO "payload_json: '%s'\n", payload_json);

    JSON_Value *payload = json_parse_string(payload_json);
    if (!payload)
    {
        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        json_value_free(header);
        return NULL;
    }

    JSON_Object *payload_obj = json_value_get_object(payload);

    j->iss = json_object_get_string(payload_obj, "iss");
    j->sub = json_object_get_string(payload_obj, "sub");
    j->aud = json_object_get_string(payload_obj, "aud");
    j->exp = json_object_get_number(payload_obj, "exp");

    // signature parsing
    char *signature = payload_end + 1;

    printk("calculating hash for [%d bytes]: %.*s", payload_end - jwt, payload_end - jwt, jwt);

    char *hash = hmac_sha256(jwt, payload_end - jwt, secret);
    if (!hash)
    {
        printk(KERN_ERR "failed to calculate hmac");

        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        json_value_free(header);

        return NULL;
    }

    char hash_base64[256];

    int bytes = base64_encode(hash_base64, 256, hash, 32);

    if (bytes < 0)
    {
        printk(KERN_ERR "failed to base64 encode signature");

        kfree(j);
        kfree(header_json);
        kfree(payload_json);
        json_value_free(header);

        return NULL;
    }

    printk("signature   [%d bytes]: %s", strlen(signature), signature);
    printk("hash_base64 [%d bytes]: %s", bytes, hash_base64);

    return j;
}

void jwt_free(jwt_t *jwt)
{
    kfree(jwt);
}
