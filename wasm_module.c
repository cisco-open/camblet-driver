#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

#include "device_driver.h"
#include "netfilter.h"
#include "wasm_module.h"
#include "wasm3/source/m3_api_libc.h"

#define PRIi32 "i"
#define PRIi64 "lli"

#define MAX_MODULES 16

static IM3Environment env;
static IM3Runtime runtime;

static u8 *wasm_bins[MAX_MODULES];
static int wasm_bins_qty = 0;

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
//     (import "env" "clock_ms" (func $clock_ms (param) (result i32)))
//     (type $sum_t (func (param i32 i32) (result i32)))
//     (func $sum_f (type $sum_t) (param $x i32) (param $y i32) (result i32)
//       (call $clock_ms)
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

M3Result link_all(IM3Module module)
{
    M3Result res;
    res = m3_LinkSpecTest(module);
    if (res)
        return res;

    res = m3_LinkLibC(module);
    if (res)
        return res;

#if defined(LINK_WASI)
    res = m3_LinkWASI(module);
    if (res)
        return res;
#endif

#if defined(d_m3HasTracer)
    res = m3_LinkTracer(module);
    if (res)
        return res;
#endif

#if defined(GAS_LIMIT)
    res = m3_LinkRawFunction(module, "metering", "usegas", "v(i)", &metering_usegas);
    if (!res)
    {
        fprintf(stderr, "Warning: Gas is limited to %0.4f\n", (double)(current_gas) / GAS_FACTOR);
        is_gas_metered = true;
    }
    if (res == m3Err_functionLookupFailed)
    {
        res = NULL;
    }
#endif

    return res;
}

void repl_free(void)
{
    if (runtime)
    {
        m3_FreeRuntime(runtime);
        runtime = NULL;
    }

    int i;
    for (i = 0; i < wasm_bins_qty; i++)
    {
        kfree(wasm_bins[i]);
        wasm_bins[i] = NULL;
    }
}

M3Result repl_init(unsigned stack)
{
    repl_free();
    runtime = m3_NewRuntime(env, stack, NULL);
    if (runtime == NULL)
    {
        return "m3_NewRuntime failed";
    }
    return m3Err_none;
}

M3Result repl_load(const char *module_name, unsigned char wasm_code[], unsigned int wasm_code_size)
{
    M3Result result = m3Err_none;
    IM3Module module = NULL;

    u8 *wasm = NULL;

    wasm = (u8 *)kmalloc(wasm_code_size, GFP_KERNEL);
    if (!wasm)
    {
        result = "cannot allocate memory for wasm binary";
        goto on_error;
    }

    memcpy(wasm, wasm_code, wasm_code_size);

    result = m3_ParseModule(env, &module, wasm, wasm_code_size);
    if (result)
        goto on_error;

    result = m3_LoadModule(runtime, module);
    if (result)
        goto on_error;

    m3_SetModuleName(module, module_name);

    result = link_all(module);
    if (result)
        goto on_error;

    if (wasm_bins_qty < MAX_MODULES)
    {
        wasm_bins[wasm_bins_qty++] = wasm;
    }

    return result;

on_error:
    m3_FreeModule(module);
    if (wasm)
        kfree(wasm);

    return result;
}

M3Result repl_call(const char *name, int argc, const char *argv[])
{
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, name);
    if (result)
        return result;

    // if (argc && (!strcmp(name, "main") || !strcmp(name, "_main")))
    // {
    //     return "passing arguments to libc main() not implemented";
    // }

    if (!strcmp(name, "_start"))
    {
#if defined(LINK_WASI)
        // Strip wasm file path
        if (argc > 0)
        {
            argv[0] = modname_from_fn(argv[0]);
        }

        m3_wasi_context_t *wasi_ctx = m3_GetWasiContext();
        wasi_ctx->argc = argc;
        wasi_ctx->argv = argv;

        result = m3_CallArgv(func, 0, NULL);

        print_gas_used();

        if (result == m3Err_trapExit)
        {
            exit(wasi_ctx->exit_code);
        }

        return result;
#else
        return "WASI not linked";
#endif
    }

    int arg_count = m3_GetArgCount(func);
    int ret_count = m3_GetRetCount(func);
    if (argc < arg_count)
    {
        return "not enough arguments";
    }
    else if (argc > arg_count)
    {
        return "too many arguments";
    }

    result = m3_CallArgv(func, argc, argv);

    if (result)
        return result;

    static uint64_t valbuff[128];
    static const void *valptrs[128];
    memset(valbuff, 0, sizeof(valbuff));
    int i;
    for (i = 0; i < ret_count; i++)
    {
        valptrs[i] = &valbuff[i];
    }
    result = m3_GetResults(func, ret_count, valptrs);
    if (result)
        return result;

    if (ret_count <= 0)
    {
        printk("Result: <Empty Stack>\n");
    }
    for (i = 0; i < ret_count; i++)
    {
        switch (m3_GetRetType(func, i))
        {
        case c_m3Type_i32:
            printk("Result: %" PRIi32 "\n", *(i32 *)valptrs[i]);
            break;
        case c_m3Type_i64:
            printk("Result: %" PRIi64 "\n", *(i64 *)valptrs[i]);
            break;
#if d_m3HasFloat
        case c_m3Type_f32:
            printk("Result: %" PRIf32 "\n", *(f32 *)valptrs[i]);
            break;
        case c_m3Type_f64:
            printk("Result: %" PRIf64 "\n", *(f64 *)valptrs[i]);
            break;
#endif
        default:
            return "unknown return type";
        }
    }

    return result;
}

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
    env = m3_NewEnvironment();
    if (!env)
        FATAL("m3_NewEnvironment: NULL");

    unsigned argStackSize = 64 * 1024;

    result = repl_init(argStackSize);
    if (result)
        FATAL("repl_init: %s", result);

    result = repl_load("sum", hello_wasm, hello_wasm_len);
    if (result)
        FATAL("repl_load: %s", result);

    const char *args[] = {"30", "20"};

    result = repl_call("sum", 2, args);
    if (result)
        FATAL("repl_call: %s", result);

    start_netfilter_submodule();

    return chardev_init();
}

static void __exit wasm3_exit(void)
{
    stop_netfilter_submodule();
    chardev_exit();
    pr_info("%s: goodbye %s\n", MODULE_NAME, name);
    pr_info("%s: module unloaded from 0x%p\n", MODULE_NAME, wasm3_exit);
}

module_init(wasm3_init);
module_exit(wasm3_exit);
