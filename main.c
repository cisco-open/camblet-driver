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
#include "opa.h"
#include "socket.h"
#include "wasm.h"
#include "config.h"
#include "sd.h"
#include "string.h"

#include "static/filter_stats.h"
#include "static/filter_tcp_metadata.h"
#include "static/csr_wasm.h"
#include "static/socket_wasm.h"

MODULE_AUTHOR("Cisco Systems");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("NASP - Kernel Space Access Control for Zero Trust Networking");
MODULE_VERSION("0.3.0");

static bool proxywasm_modules = false;
module_param(proxywasm_modules, bool, 0644);
MODULE_PARM_DESC(proxywasm_modules, "Enable/disable the proxywasm modules");

bool ktls_available = true;
module_param(ktls_available, bool, 0644);
MODULE_PARM_DESC(ktls_available, "Marks if kTLS is available on the system");

static int __init nasp_init(void)
{
    pr_info("module loaded at 0x%p running on %d CPUs", nasp_init, nr_cpu_ids);

    wasm_vm_result result = wasm_vm_new_per_cpu();
    if (result.err)
    {
        FATAL("wasm_vm_new_per_cpu: %s", result.err);
        return -1;
    }

    nasp_config_init();
    sd_table_init();

    int ret = 0;

    ret += chardev_init();
    ret += socket_init();

    if (proxywasm_modules)
    {
        result = load_module("proxywasm_tcp_metadata_filter", filter_tcp_metadata, size_filter_tcp_metadata, "_start");
        if (result.err)
        {
            FATAL("load_module -> proxywasm_tcp_metadata_filter: %s", result.err);
            return -1;
        }

        result = load_module("proxywasm_stats_filter", filter_stats, size_filter_stats, "_initialize");
        if (result.err)
        {
            FATAL("load_module -> proxywasm_stats_filter: %s", result.err);
            return -1;
        }
    }

    result = load_module("csr_module", csr_wasm, csr_wasm_len, NULL);
    if (result.err)
    {
        FATAL("load_module -> csr_module: %s", result.err);
        return -1;
    }

    result = load_module("socket_opa", socket_wasm, socket_wasm_len, NULL);
    if (result.err)
    {
        FATAL("load_module -> socket_opa: %s", result.err);
        return -1;
    }

    return ret;
}

static void __exit nasp_exit(void)
{
    socket_exit();
    chardev_exit();
    wasm_vm_destroy_per_cpu();

    sd_table_free();
    nasp_config_free();

    pr_info("%s: module unloaded from 0x%p", THIS_MODULE->name, nasp_exit);
}

module_init(nasp_init);
module_exit(nasp_exit);
