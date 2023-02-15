#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/init.h>

#include "device_driver.h"
#include "netfilter.h"
#include "runtime.h"
#include "worker_thread.h"
#include "opa.h"

//  Define the module metadata.
#define MODULE_NAME "wasm"
MODULE_AUTHOR("Nandor Kracser");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module that exposes a wasm VM");
MODULE_VERSION("0.1");

// Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

int bpf_opa_eval(int protocol)
{
    int res = this_cpu_opa_eval(protocol);
    printk("bpf_opa_eval(protocol=0x%04x) -> %d", protocol, res);
    return res;
}

BTF_SET_START(opa_kfunc_ids)
BTF_ID(func, bpf_opa_eval)
BTF_SET_END(opa_kfunc_ids)

static const struct btf_kfunc_id_set bpf_opa_kfunc_set = {
    .owner = THIS_MODULE,
    .check_set = &opa_kfunc_ids,
};

static int __init wasm_init(void)
{
    pr_info("%s: module loaded at 0x%p running on %d CPUs\n", MODULE_NAME, wasm_init, nr_cpu_ids);

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

    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, wasm_exit);
}

module_init(wasm_init);
module_exit(wasm_exit);
