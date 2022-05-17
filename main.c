#include <linux/module.h>

#include "device_driver.h"
#include "netfilter.h"
#include "runtime.h"
#include "worker_thread.h"

//   (module
//     (type $sum_t (func (param i32 i32) (result i32)))
//     (func $sum_f (type $sum_t) (param $x i32) (param $y i32) (result i32)
//       local.get $x
//       local.get $y
//       i32.add)
//     (export "sum" (func $sum_f)))
unsigned char sum_wasm[] = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01,
    0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x73, 0x75, 0x6d, 0x00, 0x00, 0x0a, 0x09,
    0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, 0x00, 0x24, 0x04, 0x6e, 0x61, 0x6d, 0x65,
    0x01, 0x08, 0x01, 0x00, 0x05, 0x73, 0x75, 0x6d, 0x5f, 0x66, 0x02, 0x09, 0x01, 0x00, 0x02, 0x00,
    0x01, 0x78, 0x01, 0x01, 0x79, 0x04, 0x08, 0x01, 0x00, 0x05, 0x73, 0x75, 0x6d, 0x5f, 0x74,
};

unsigned int sum_wasm_len = 79;

//   (module
//     (import "env" "printf" (func $printf (param i32 i32) (result i32)))
//     (import "env" "clock_ns" (func $clock_ns (param) (result i64)))
//     (type $sum_t (func (param i32 i32) (result i32)))
//     (func $sum_f (type $sum_t) (param $x i32) (param $y i32) (result i32)
//       (call $clock_ns)
//     ;;   local.get $x
//       local.get $y
//       i32.add)
//     (export "sum" (func $sum_f)))
unsigned char hello_wasm[] = {
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x02, 0x60,
  0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x02, 0x1d, 0x02,
  0x03, 0x65, 0x6e, 0x76, 0x06, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x66, 0x00,
  0x00, 0x03, 0x65, 0x6e, 0x76, 0x08, 0x63, 0x6c, 0x6f, 0x63, 0x6b, 0x5f,
  0x6d, 0x73, 0x00, 0x01, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03,
  0x73, 0x75, 0x6d, 0x00, 0x02, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x10, 0x01,
  0x20, 0x01, 0x6a, 0x0b
};
unsigned int hello_wasm_len = 76;

//  Define the module metadata.
#define MODULE_NAME "wasm3"
MODULE_AUTHOR("Nandor Kracser");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A kernel module that runs wasm3");
MODULE_VERSION("0.1");

//  Define the name parameter.
static char *name = "Bilbo";
module_param(name, charp, S_IRUGO);
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");

static int __init wasm3_init(void)
{
    pr_info("%s: module loaded at 0x%p\n", MODULE_NAME, wasm3_init);

    M3Result result = m3Err_none;

    result = repl_init(STACK_SIZE_BYTES);
    if (result)
        FATAL("repl_init: %s", result);

    // result = repl_load("sum", hello_wasm, hello_wasm_len);
    // if (result)
    //     FATAL("repl_load: %s", result);

    // const char *args[] = {"30", "20"};

    // result = repl_call("sum", 2, args);
    // if (result)
    //     FATAL("repl_call: %s", result);

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
