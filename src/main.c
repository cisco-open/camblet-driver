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

#include <linux/module.h>

#include "device_driver.h"
#include "csr.h"
#include "opa.h"
#include "socket.h"
#include "wasm.h"
#include "config.h"
#include "sd.h"
#include "string.h"
#include "jwt.h"

#include "static/filter_stats.h"
#include "static/filter_tcp_metadata.h"
#include "static/csr_wasm.h"
#include "static/socket_wasm.h"

MODULE_AUTHOR("Camblet Maintainers <team@camblet.io>");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Camblet - Kernel Space Access Control for Zero Trust Networking");
MODULE_VERSION("0.7.1");
MODULE_SOFTDEP("pre: tls");

static bool proxywasm_modules = false;
module_param(proxywasm_modules, bool, 0644);
MODULE_PARM_DESC(proxywasm_modules, "Enable/disable the proxywasm modules");

bool ktls_available = true;
module_param(ktls_available, bool, 0644);
MODULE_PARM_DESC(ktls_available, "Marks if kTLS is available on the system");

typedef struct camblet_init_status
{
    bool wasm;
    bool wasm_opa;
    bool wasm_csr;
    bool chardev;
    bool socket;
    bool sd_table;
    bool config;
} camblet_init_status;

camblet_init_status __camblet_init_status = {0};

static void __camblet_exit(void)
{
    if (__camblet_init_status.socket)
        socket_exit();
    if (__camblet_init_status.chardev)
        chardev_exit();
    if (__camblet_init_status.wasm_csr)
        free_csr_modules();
    if (__camblet_init_status.wasm_opa)
        free_opa_modules();
    if (__camblet_init_status.wasm)
        wasm_vm_destroy_per_cpu();
    if (__camblet_init_status.sd_table)
        sd_table_free();
    if (__camblet_init_status.config)
        camblet_config_free();
}

static int __init camblet_init(void)
{
    int ret = 0;

    pr_info("load module at 0x%p running on %d CPUs", camblet_init, num_online_cpus());

    wasm_vm_result result = wasm_vm_new_per_cpu();
    if (result.err)
    {
        FATAL("wasm_vm_new_per_cpu: %s", result.err);
        ret = -1;
        goto out;
    }
    __camblet_init_status.wasm = true;

    ret = camblet_config_init();
    if (ret < 0)
    {
        FATAL("could not init config: %d", ret);
        goto out;
    }
    __camblet_init_status.config = true;

    ret = sd_table_init();
    if (ret < 0)
    {
        FATAL("could not init sd table: %d", ret);
        goto out;
    }
    __camblet_init_status.sd_table = true;

    ret = chardev_init();
    if (ret < 0)
    {
        FATAL("could not init char device: %d", ret);
        goto out;
    }
    __camblet_init_status.chardev = true;

    ret = socket_init();
    if (ret < 0)
    {
        FATAL("could not init socket proto: %d", ret);
        goto out;
    }
    __camblet_init_status.socket = true;

    if (proxywasm_modules)
    {
        result = load_module("proxywasm_tcp_metadata_filter", filter_tcp_metadata, size_filter_tcp_metadata, "_start");
        if (result.err)
        {
            FATAL("load_module -> proxywasm_tcp_metadata_filter: %s", result.err);
            ret = -1;
            goto out;
        }

        result = load_module("proxywasm_stats_filter", filter_stats, size_filter_stats, "_initialize");
        if (result.err)
        {
            FATAL("load_module -> proxywasm_stats_filter: %s", result.err);
            ret = -1;
            goto out;
        }
    }

    result = load_module("csr_module", csr_wasm, csr_wasm_len, NULL);
    if (result.err)
    {
        FATAL("load_module -> csr_module: %s", result.err);
        ret = -1;
        goto out;
    }

    __camblet_init_status.wasm_csr = true;

    result = load_module("socket_opa", socket_wasm, socket_wasm_len, NULL);
    if (result.err)
    {
        FATAL("load_module -> socket_opa: %s", result.err);
        ret = -1;
        goto out;
    }

    __camblet_init_status.wasm_opa = true;

    // test jwt
    jwt_t *jwt = jwt_parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kGWDzjy0MXc1UiDVSZNAoFQMeVKBievVdGmTE1fOEXg", "no");
    if (jwt)
    {
        pr_info("jwt: alg=%s, typ=%s, iss=%s, sub=%s, aud=%s, exp=%llu", jwt->alg, jwt->typ, jwt->iss, jwt->sub, jwt->aud, jwt->exp);
        jwt_free(jwt);
    }
    else
    {
        pr_err("jwt: failed to parse");
    }

out:
    if (ret < 0)
        __camblet_exit();
    else
        pr_info("module loaded at 0x%p running on %d CPUs", camblet_init, num_online_cpus());

    return ret;
}

static void __exit camblet_exit(void)
{
    __camblet_exit();

    pr_info("%s: module unloaded from 0x%p", KBUILD_MODNAME, camblet_exit);
}

module_init(camblet_init);
module_exit(camblet_exit);
