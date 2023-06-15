/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/mm.h>
#include <linux/bpfptr.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

#include "crypto.h"
#include "device_driver.h"
#include "netfilter.h"
#include "runtime.h"
#include "worker_thread.h"
#include "opa.h"
#include "socket.h"

#include "filter_stats.h"
#include "filter_tcp_metadata.h"

MODULE_AUTHOR("Cisco Systems");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("A kernel module that exposes a wasm VM");
MODULE_VERSION("0.1");

int bpf_opa_eval(const char *input)
{
    int res = this_cpu_opa_eval(input);
    printk("%s: bpf_opa_eval(input=%s) -> %d", THIS_MODULE->name, input, res);
    return res;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)

#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 0, 0)
BTF_SET8_START(opa_kfunc_ids)
BTF_ID_FLAGS(func, bpf_opa_eval)
BTF_SET8_END(opa_kfunc_ids)
#else
BTF_SET_START(opa_kfunc_ids)
BTF_ID(func, bpf_opa_eval)
BTF_SET_END(opa_kfunc_ids)
#endif

static const struct btf_kfunc_id_set bpf_opa_kfunc_set = {
    .owner = THIS_MODULE,
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 0, 0)
    .set = &opa_kfunc_ids,
#else
    .check_set = &opa_kfunc_ids,
#endif
};

#endif

static int __init wasm_init(void)
{
    pr_info("%s: module loaded at 0x%p running on %d CPUs", THIS_MODULE->name, wasm_init, nr_cpu_ids);

    wasm_vm_result result = wasm_vm_new_per_cpu();
    if (result.err)
    {
        FATAL("wasm_vm_new_per_cpu: %s", result.err);
        return -1;
    }

    int ret = 0;

    ret += start_netfilter_submodule();
    ret += worker_thread_init();
    ret += chardev_init();
    ret += wasm_socket_init();

    result = load_module("proxywasm_tcp_metadata_filter", filter_tcp_metadata, size_filter_tcp_metadata, "_start");
    if (result.err)
    {
        FATAL("load_module -> proxywasm_tcp_metadata_filter: %s", result.err);
        return -1;
    }

    // result = load_module("proxywasm_stats_filter", filter_stats, size_filter_stats, "_initialize");
    // if (result.err)
    // {
    //     FATAL("load_module -> proxywasm_stats_filter: %s", result.err);
    //     return -1;
    // }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
    ret += register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_opa_kfunc_set);
#else
    pr_warn("%s: your kernel version (<5.18) doesn't support BTF kfuncs, can't register them", THIS_MODULE->name);
#endif

    struct key *key = request_rsa_key("wasm-test", NULL);
    if (IS_ERR(key))
    {
        pr_err("%s: request_rsa_key failed", THIS_MODULE->name);
    } else {
        printk("%s: request_rsa_key -> %p", THIS_MODULE->name, key);
    }
 
    return ret;
}

static void __exit wasm_exit(void)
{
    wasm_socket_exit();
    chardev_exit();
    stop_netfilter_submodule();
    worker_thread_exit();
    wasm_vm_destroy_per_cpu();

    pr_info("%s: module unloaded from 0x%p", THIS_MODULE->name, wasm_exit);
}

module_init(wasm_init);
module_exit(wasm_exit);
