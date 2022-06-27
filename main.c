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
    pr_info("%s: module loaded at 0x%p\n", MODULE_NAME, wasm3_init);

    M3Result result = repl_init(STACK_SIZE_BYTES);
    if (result)
        FATAL("repl_init: %s", result);

    start_netfilter_submodule();

    worker_thread_init();

    return chardev_init();
}

static void __exit wasm3_exit(void)
{
    chardev_exit();
    stop_netfilter_submodule();
    worker_thread_exit();
    repl_free();

    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, wasm3_exit);
}

module_init(wasm3_init);
module_exit(wasm3_exit);
