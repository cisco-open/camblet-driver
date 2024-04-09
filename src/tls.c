/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include "tls.h"
#include "trace.h"
#include "string.h"

#include <linux/slab.h>

const unsigned char OID_rfc822Name[] = {0, 1};
const unsigned char OID_dNSName[] = {0, 2};
const unsigned char OID_uniformResourceIdentifier[] = {0, 6};

#define tlsHandshakeRecord 22
#define VersionTLS10 0x0301
#define VersionTLS11 0x0302
#define VersionTLS12 0x0303
#define VersionTLS13 0x0304

bool is_tls_handshake(const uint8_t *b)
{
    if (b[0] != tlsHandshakeRecord)
    {
        return false;
    }

    uint16_t tlsVersion = (b[1] << 8) | b[2];

    switch (tlsVersion)
    {
    case VersionTLS10:
    case VersionTLS11:
    case VersionTLS12:
    case VersionTLS13:
        return true;
    default:
        return false;
    }
}

static int compare_spiffe_ids(const char *allowed_id, const char *id)
{
    int allowed_id_len = strlen(allowed_id);
    int id_len = strlen(id);
    int ret = strncmp(allowed_id, id, allowed_id_len);
    if (ret == 0)
    {
        if (allowed_id_len == id_len)
        {
            return 0;
        }
        else if (id_len > allowed_id_len)
        {
            if (id[allowed_id_len] == '/')
            {
                return 0;
            }
            else
            {
                return 1;
            }
        }
    }
    return ret;
}

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_camblet_context *)(void *)ctx)->ctx;
    cc->vtable->start_chain(&cc->vtable, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_camblet_context *)(void *)ctx)->ctx;
    cc->vtable->start_cert(&cc->vtable, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_camblet_context *)(void *)ctx)->ctx;
    cc->vtable->append(&cc->vtable, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_camblet_context *)(void *)ctx)->ctx;
    cc->vtable->end_cert(&cc->vtable);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
    br_x509_minimal_context *mini_cc;
    br_x509_camblet_context *camblet_cc;

    camblet_cc = ((br_x509_camblet_context *)(void *)ctx);
    mini_cc = &camblet_cc->ctx;

    unsigned int err = mini_cc->vtable->end_chain(&mini_cc->vtable);

    if (err == BR_ERR_X509_NOT_TRUSTED && camblet_cc->insecure)
    {
        pr_warn("end chain error # err[%d], but using skip-verify now", err);
        return 0;
    }
    else if (err != 0)
    {
        return err;
    }

    int i, k;
    bool allowed = true;

    if (camblet_cc->socket_context->allowed_spiffe_ids_length > 0)
    {
        allowed = false;
    }

    pr_debug("allowed spiffe id count # count[%d]", camblet_cc->socket_context->allowed_spiffe_ids_length);

    char *spiffe_id = NULL;

    for (i = 0; i < mini_cc->num_name_elts; i++)
    {
        pr_debug("peer certificate # name_elts[%d] status[%d] value[%s] len[%ld]", i, mini_cc->name_elts[i].status, mini_cc->name_elts[i].buf, mini_cc->name_elts[i].len);

        if (mini_cc->name_elts[i].oid == OID_uniformResourceIdentifier)
        {
            if (camblet_cc->conn_ctx->peer_spiffe_id == NULL && mini_cc->name_elts[i].buf != NULL)
            {
                camblet_cc->conn_ctx->peer_spiffe_id = kstrdup(mini_cc->name_elts[i].buf, GFP_KERNEL);
                if (!camblet_cc->conn_ctx->peer_spiffe_id)
                {
                    pr_crit("xwc_end_chain: could not allocate memory");
                    break;
                }
            }

            spiffe_id = mini_cc->name_elts[i].buf;
            for (k = 0; k < camblet_cc->socket_context->allowed_spiffe_ids_length; k++)
            {
                if (compare_spiffe_ids(camblet_cc->socket_context->allowed_spiffe_ids[k], mini_cc->name_elts[i].buf) == 0)
                {
                    trace_debug(camblet_cc->conn_ctx, "peer certificate allowed", 4, "peer-spiffe-id", mini_cc->name_elts[i].buf, "allowed-spiffe-id", camblet_cc->socket_context->allowed_spiffe_ids[k]);
                    allowed = true;
                    break;
                }
            }
        }
    }

    if (!allowed)
    {
        trace_debug(camblet_cc->conn_ctx, "peer certificate is denied", 2, "peer-spiffe-id", spiffe_id);

        return BR_ERR_X509_NOT_TRUSTED;
    }

    return 0;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_camblet_context *)(void *)ctx)->ctx;
    return cc->vtable->get_pkey(&cc->vtable, usages);
}

static const br_x509_class x509_camblet_vtable = {
    sizeof(br_x509_camblet_context),
    xwc_start_chain,
    xwc_start_cert,
    xwc_append,
    xwc_end_cert,
    xwc_end_chain,
    xwc_get_pkey,
};

static void br_x509_name_elts_free(br_name_element *name_elts, size_t num);

int br_x509_camblet_init(br_x509_camblet_context *ctx, br_ssl_engine_context *eng, opa_socket_context *socket_context, tcp_connection_context *conn_ctx, bool insecure)
{
    br_name_element *name_elts = kmalloc(sizeof(br_name_element) * 3, GFP_KERNEL);
    if (!name_elts)
        return -ENOMEM;

    char const *oids[] = {OID_rfc822Name, OID_dNSName, OID_uniformResourceIdentifier};

    int i;
    int num = 0;
    for (i = 0; i < sizeof(oids) / sizeof(oids[0]); i++)
    {
        name_elts[i].oid = oids[i];
        name_elts[i].buf = kmalloc(sizeof(char) * 256, GFP_KERNEL);
        if (!name_elts[i].buf)
        {
            br_x509_name_elts_free(name_elts, num);
            return -ENOMEM;
        }
        name_elts[i].len = 256;
        num++;
    }

    ctx->vtable = &x509_camblet_vtable;
    ctx->socket_context = socket_context;
    ctx->conn_ctx = conn_ctx;
    ctx->insecure = insecure;

    br_x509_minimal_set_name_elements(&ctx->ctx, name_elts, num);
    br_ssl_engine_set_x509(eng, &ctx->vtable);

    return 0;
}

static void br_x509_name_elts_free(br_name_element *name_elts, size_t num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        kfree(name_elts[i].buf);
    }
    kfree(name_elts);
}

void br_x509_camblet_free(br_x509_camblet_context *ctx)
{
    br_x509_name_elts_free(ctx->ctx.name_elts, ctx->ctx.num_name_elts);
}

void setup_aes_gcm_128_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq)
{
    crypto_info->cipher.gcm_128.info.version = TLS_1_2_VERSION;
    crypto_info->cipher.gcm_128.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto_info->cipher.gcm_128.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(crypto_info->cipher.gcm_128.salt, iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    uint64_t swapseq = m3_bswap64(seq);
    memcpy(crypto_info->cipher.gcm_128.iv, &swapseq, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(crypto_info->cipher.gcm_128.rec_seq, &swapseq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    crypto_info->cipher_type_len = sizeof(crypto_info->cipher.gcm_128);
}

void setup_aes_gcm_256_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq)
{
    crypto_info->cipher.gcm_256.info.version = TLS_1_2_VERSION;
    crypto_info->cipher.gcm_256.info.cipher_type = TLS_CIPHER_AES_GCM_256;

    memcpy(crypto_info->cipher.gcm_256.key, key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
    memcpy(crypto_info->cipher.gcm_256.salt, iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);

    uint64_t swapseq = m3_bswap64(seq);
    memcpy(crypto_info->cipher.gcm_256.iv, &swapseq, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    memcpy(crypto_info->cipher.gcm_256.rec_seq, &swapseq, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

    crypto_info->cipher_type_len = sizeof(crypto_info->cipher.gcm_256);
}

void setup_chacha_poly_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq)
{
    crypto_info->cipher.chapol.info.version = TLS_1_2_VERSION;
    crypto_info->cipher.chapol.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;

    memcpy(crypto_info->cipher.chapol.iv, iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
    memcpy(crypto_info->cipher.chapol.key, key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);

    uint64_t swapseq = m3_bswap64(seq);
    memcpy(crypto_info->cipher.chapol.rec_seq, &swapseq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
    crypto_info->cipher_type_len = sizeof(crypto_info->cipher.chapol);
}

void setup_aes_ccm_128_crypto_info(crypto_info *crypto_info, const uint8_t *iv, const uint8_t *key, uint64_t seq)
{
    crypto_info->cipher.ccm_128.info.version = TLS_1_2_VERSION;
    crypto_info->cipher.ccm_128.info.cipher_type = TLS_CIPHER_AES_CCM_128;

    memcpy(crypto_info->cipher.ccm_128.salt, iv, TLS_CIPHER_AES_CCM_128_SALT_SIZE);
    memcpy(crypto_info->cipher.ccm_128.key, key, TLS_CIPHER_AES_CCM_128_KEY_SIZE);

    uint64_t swapseq = m3_bswap64(seq);
    memcpy(crypto_info->cipher.ccm_128.iv, &swapseq, TLS_CIPHER_AES_CCM_128_IV_SIZE);
    memcpy(crypto_info->cipher.ccm_128.rec_seq, &swapseq, TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE);
    crypto_info->cipher_type_len = sizeof(crypto_info->cipher.ccm_128);
}

bool is_cipher_supported(uint16_t cipher_suite)
{
    return cipher_suite == BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
           cipher_suite == BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
           cipher_suite == BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
           cipher_suite == BR_TLS_RSA_WITH_AES_128_CCM;
}