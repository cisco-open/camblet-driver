/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "tls.h"

#include <linux/slab.h>

const unsigned char OID_rfc822Name[] = {0, 1};
const unsigned char OID_dNSName[] = {0, 2};
const unsigned char OID_uniformResourceIdentifier[] = {0, 6};

static void
xwc_start_chain(const br_x509_class **ctx, const char *server_name)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_nasp_context *)(void *)ctx)->ctx;
    cc->vtable->start_chain(&cc->vtable, server_name);
}

static void
xwc_start_cert(const br_x509_class **ctx, uint32_t length)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_nasp_context *)(void *)ctx)->ctx;
    cc->vtable->start_cert(&cc->vtable, length);
}

static void
xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_nasp_context *)(void *)ctx)->ctx;
    cc->vtable->append(&cc->vtable, buf, len);
}

static void
xwc_end_cert(const br_x509_class **ctx)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_nasp_context *)(void *)ctx)->ctx;
    cc->vtable->end_cert(&cc->vtable);
}

static unsigned
xwc_end_chain(const br_x509_class **ctx)
{
    br_x509_minimal_context *mini_cc;
    br_x509_nasp_context *nasp_cc;

    nasp_cc = ((br_x509_nasp_context *)(void *)ctx);
    mini_cc = &nasp_cc->ctx;

    unsigned int err = mini_cc->vtable->end_chain(&mini_cc->vtable);
    if (err)
        return err;

    for (int i = 0; i < mini_cc->num_name_elts; i++)
    {
        printk("nasp: peer certificate name_elts[%d]: status: %d, value: %s", i, mini_cc->name_elts[i].status, mini_cc->name_elts[i].buf);
    }

    return 0;
}

static const br_x509_pkey *
xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    br_x509_minimal_context *cc;
    cc = &((br_x509_nasp_context *)(void *)ctx)->ctx;
    return cc->vtable->get_pkey(&cc->vtable, usages);
}

static const br_x509_class x509_nasp_vtable = {
    sizeof(br_x509_nasp_context),
    xwc_start_chain,
    xwc_start_cert,
    xwc_append,
    xwc_end_cert,
    xwc_end_chain,
    xwc_get_pkey,
};

void br_x509_nasp_init(br_x509_nasp_context *ctx, br_ssl_engine_context *eng)
{
    ctx->vtable = &x509_nasp_vtable;

    br_name_element *name_elts = kmalloc(sizeof(br_name_element) * 3, GFP_KERNEL);

    char const *oids[] = {OID_rfc822Name, OID_dNSName, OID_uniformResourceIdentifier};
    for (int i = 0; i < sizeof(oids) / sizeof(oids[0]); i++)
    {
        name_elts[i].oid = oids[i];
        name_elts[i].buf = kmalloc(sizeof(char) * 256, GFP_KERNEL);
        name_elts[i].len = 256;
    }

    br_x509_minimal_set_name_elements(&ctx->ctx, name_elts, sizeof(oids) / sizeof(oids[0]));

    br_ssl_engine_set_x509(eng, &ctx->vtable);
}

void br_x509_nasp_free(br_x509_nasp_context *ctx)
{
    for (int i = 0; i < ctx->ctx.num_name_elts; i++)
    {
        kfree(ctx->ctx.name_elts[i].buf);
    }
    kfree(ctx->ctx.name_elts);
}
