/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

#include "device_driver.h"
#include "netfilter.h"
#include "runtime.h"
#include "worker_thread.h"
#include "opa.h"

MODULE_AUTHOR("Nandor Kracser");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("A kernel module that exposes a wasm VM");
MODULE_VERSION("0.1");

int bpf_opa_eval(const char *input)
{
    int res = this_cpu_opa_eval(input);
    printk("%s: bpf_opa_eval(input=%s) -> %d", THIS_MODULE->name, input, res);
    return res;
}

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

static int __init wasm_init(void)
{
    pr_info("%s: module loaded at 0x%p running on %d CPUs\n", THIS_MODULE->name, wasm_init, nr_cpu_ids);

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
    ret += register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_opa_kfunc_set);

    return ret;
}

static void __exit wasm_exit(void)
{
    chardev_exit();
    stop_netfilter_submodule();
    worker_thread_exit();
    wasm_vm_destroy_per_cpu();

    pr_info("%s: module unloaded from 0x%p\n", THIS_MODULE->name, wasm_exit);
}

module_init(wasm_init);
module_exit(wasm_exit);
