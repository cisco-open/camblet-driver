/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef tls_h
#define tls_h

#include "bearssl.h"
#include "opa.h"
#include "socket.h"
#include <net/tls.h>

/*
 * This is a wrapper around the BearSSL X.509 validation engine. It
 * implements the br_x509_class interface, and forwards calls to a
 * br_x509_minimal_context instance. The wrapper is needed because the
 * br_x509_minimal_context structure is not doing anything interesting
 * with the DN and SAN fields, and we want to be able to access them.
 */
typedef struct br_x509_camblet_context
{
    const br_x509_class *vtable;
    br_x509_minimal_context ctx;
    opa_socket_context *socket_context;
    tcp_connection_context *conn_ctx;
    bool insecure;
} br_x509_camblet_context;

typedef struct crypto_info
{
    union
    {
        struct tls12_crypto_info_aes_ccm_128 ccm_128;
        struct tls12_crypto_info_aes_gcm_128 gcm_128;
        struct tls12_crypto_info_aes_gcm_256 gcm_256;
        struct tls12_crypto_info_chacha20_poly1305 chapol;
    } cipher;
    size_t cipher_type_len;
} crypto_info;

void br_x509_camblet_init(br_x509_camblet_context *ctx, br_ssl_engine_context *eng, opa_socket_context *socket_context, tcp_connection_context *conn_ctx, bool insecure);
void br_x509_camblet_free(br_x509_camblet_context *ctx);

bool is_tls_handshake(const uint8_t *b);

void setup_aes_ccm_128_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq);
void setup_aes_gcm_128_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq);
void setup_aes_gcm_256_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq);
void setup_chacha_poly_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq);
bool is_cipher_supported(uint16_t cipher_suite);
#endif
