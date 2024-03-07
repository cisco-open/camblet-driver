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

#define JWT_HEADER_MAX_SIZE 64
#define JWT_PAYLOAD_MAX_SIZE 1024

static char *json_string_get(struct json json, const char *key)
{
    struct json value = json_object_get(json, key);
    if (!json_exists(value))
    {
        return NULL;
    }

    size_t length = json_string_length(value);
    char *str = kzalloc(length + 1, GFP_KERNEL);
    if (!str)
    {
        return NULL;
    }

    json_string_copy(value, str, length + 1);

    return str;
}

jwt_t *jwt_parse(const char *jwt, const unsigned len)
{
    jwt_t *j = kzalloc(sizeof(jwt_t), GFP_KERNEL);
    if (!j)
    {
        return NULL;
    }

    char *header_end = memchr(jwt, '.', len);
    if (!header_end)
    {
        kfree(j);
        return NULL;
    }

    int header_len = header_end - jwt;
    // this is base64url encoded header so we can use 4/3 * header_len
    header_len = (header_len * 4) / 3 + 1;

    if (header_len > JWT_HEADER_MAX_SIZE)
    {
        kfree(j);
        return NULL;
    }

    char *header_json = kzalloc(header_len, GFP_KERNEL);
    if (!header_json)
    {
        kfree(j);
        return NULL;
    }

    int err = base64_decode(header_json, header_len, jwt, header_end - jwt);
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

    j->alg = json_string_get(header, "alg");

    char *payload_end = memchr(header_end + 1, '.', len - (header_end - jwt) - 1);
    if (!payload_end)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    int payload_len = payload_end - header_end - 1;
    // this is base64url encoded payload so we can use 4/3 * payload_len
    payload_len = (payload_len * 4) / 3 + 1;

    if (payload_len > JWT_PAYLOAD_MAX_SIZE)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    char *payload_json = kzalloc(payload_len, GFP_KERNEL);
    if (!payload_json)
    {
        kfree(j);
        kfree(header_json);
        return NULL;
    }

    err = base64_decode(payload_json, payload_len, header_end + 1, payload_end - header_end - 1);
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

    j->iss = json_string_get(payload, "iss");
    j->sub = json_string_get(payload, "sub");
    j->aud = json_string_get(payload, "aud");
    j->exp = json_uint64(json_object_get(payload, "exp"));
    j->iat = json_uint64(json_object_get(payload, "iat"));

    // signature parsing
    j->signature = payload_end + 1;
    j->signature_len = jwt + len - j->signature;

    j->data = jwt;
    j->data_len = payload_end - jwt;

    // free all values
    kfree(header_json);
    kfree(payload_json);

    return j;
}

void jwt_free(jwt_t *jwt)
{
    if (!jwt)
        return;

    kfree(jwt->alg);
    kfree(jwt->iss);
    kfree(jwt->sub);
    kfree(jwt->aud);
    kfree(jwt);
}

int jwt_verify(jwt_t *jwt, const char *secret, const unsigned secret_len)
{
    printk("calculating hash for [%d bytes]: %.*s", jwt->data_len, jwt->data_len, jwt->data);

    if (strcmp(jwt->alg, "HS256") != 0)
    {
        pr_warn("unsupported jwt alg: %s", jwt->alg);
        return -1;
    }

    char *hash = hmac_sha256(jwt->data, jwt->data_len, secret, secret_len);
    if (!hash)
    {
        pr_err("failed to calculate hmac for jwt");

        return -1;
    }

    char signature[64];

    int bytes = base64_decode(signature, sizeof(signature), jwt->signature, jwt->signature_len);
    if (bytes < 0)
    {
        pr_err("failed to base64 decode signature");

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
