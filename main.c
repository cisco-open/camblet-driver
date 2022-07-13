#include <linux/module.h>

#include "device_driver.h"
#include "netfilter.h"
#include "runtime.h"
#include "worker_thread.h"

//  Define the module metadata.
#define MODULE_NAME "wasm3"
MODULE_AUTHOR("Nandor Kracser");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module that runs wasm3");
MODULE_VERSION("0.1");

// Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

static int __init wasm3_init(void)
{
    pr_info("%s: module loaded at 0x%p running on %d CPUs\n", MODULE_NAME, wasm3_init, nr_cpu_ids);

    wasm_vm_result result = wasm_vm_new_per_cpu();
    if (result.err)
        FATAL("wasm_vm_new_per_cpu: %s", result.err);

    start_netfilter_submodule();

    worker_thread_init();

    return chardev_init();
}

static void __exit wasm3_exit(void)
{
    chardev_exit();
    stop_netfilter_submodule();
    worker_thread_exit();
    wasm_vm_destroy_per_cpu();

    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, wasm3_exit);
}

module_init(wasm3_init);
module_exit(wasm3_exit);
