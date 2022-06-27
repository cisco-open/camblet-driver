#include <linux/slab.h>

#include "runtime.h"
#include "worker_thread.h"

#include "wasm3/source/wasm3.h"
#include "wasm3/source/m3_env.h"
#include "wasm3/source/m3_api_libc.h"
#include "wasm3/source/m3_exception.h"

#define PRIi32 "i"
#define PRIi64 "lli"

#define MAX_MODULES 16

typedef uint32_t wasm_ptr_t;
typedef uint32_t wasm_size_t;

static IM3Environment env;
static IM3Runtime runtime;

static u8 *wasm_bins[MAX_MODULES];
static int wasm_bins_qty = 0;

static M3Result link_all(IM3Module module);

void repl_free(void)
{
    if (runtime)
    {
        m3_FreeRuntime(runtime);
        runtime = NULL;
    }

    if (env)
    {
        m3_FreeEnvironment(env);
        env = NULL;
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

    env = m3_NewEnvironment();
    if (env == NULL)
    {
        return "m3_NewEnvironment failed";
    }

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

    char *moduleName = kmalloc(strlen(module_name), GFP_KERNEL);
    strcpy(moduleName, module_name);
    m3_SetModuleName(module, moduleName);

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
    {
        kfree(wasm);
        kfree(moduleName);
    }

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
    {
        print_backtrace();
        return result;
    }

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

M3Result repl_call_void(const char *name, ...)
{
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, name);
    if (result)
        return result;

    va_list ap;
    va_start(ap, func);
    result = m3_CallVL(func, ap);
    va_end(ap);

    if (result)
        print_backtrace();

    return result;
}

i32 repl_call_i32(const char *name, ...)
{
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, name);
    if (result)
    {
        printk("wasm3: repl_call_i32 %s", result);
        return -1;
    }

    int ret_count = m3_GetRetCount(func);
    if (ret_count != 1)
    {
        printk("wasm3: repl_call_i32 mismatched return count: %d", ret_count);
        return -1;
    }

    va_list ap;
    va_start(ap, func);
    result = m3_CallVL(func, ap);
    va_end(ap);

    if (result)
    {
        printk("wasm3: repl_call_i32 %s", result);
        print_backtrace();
        return -1;
    }

    static uint64_t valbuff[1];
    static const void *valptrs[1];
    memset(valbuff, 0, sizeof(valbuff));
    int i;
    for (i = 0; i < ret_count; i++)
    {
        valptrs[i] = &valbuff[i];
    }
    result = m3_GetResults(func, ret_count, valptrs);
    if (result)
    {
        printk("wasm3: repl_call_i32 %s", result);
        return -1;
    }

    if (ret_count <= 0)
    {
        printk("wasm3: repl_call_i32 <Empty Stack>");
        return -1;
    }

    switch (m3_GetRetType(func, 0))
    {
    case c_m3Type_i32:
        return *(i32 *)valptrs[0];
    default:
        printk("wasm3: repl_call_i32 unknown return type");
        return -1;
    }
}

uint8_t *repl_get_memory()
{
    uint32_t len;
    if (!runtime->memory.mallocated)
    {
        return 0;
    }
    return m3_GetMemory(runtime, &len, 0);
}

uint64_t repl_global_get(const char *name)
{
    IM3Global g = m3_FindGlobal(runtime->modules, name);

    M3TaggedValue tagged;
    M3Result err = m3_GetGlobal(g, &tagged);
    if (err)
        return 0;

    switch (tagged.type)
    {
    case c_m3Type_i32:
        return tagged.value.i32;
    case c_m3Type_i64:
        return tagged.value.i64;
    default:
        return 0;
    }
}

i32 wasm_malloc(unsigned size)
{
    return repl_call_i32("malloc", size);
}

void wasm_free(i32 ptr, unsigned size)
{
    M3Result result = repl_call_void("free", ptr, size);
    if (result)
        FATAL("wasm3: free error: %s", result);
}

m3ApiRawFunction(m3_ext_submit_metric)
{
    m3ApiReturnType (uint32_t)
    
    m3ApiGetArgMem  (void*,           i_ptr)
    m3ApiGetArg     (wasm_size_t,     i_size)

    m3ApiCheckMem(i_ptr, i_size);
    
    char *metric_line = (char *)kmalloc(i_size, GFP_KERNEL);
    if (!metric_line)
    {
        printk("cannot allocate memory for metric_line");
        m3ApiReturn(0);
    }

    memcpy(metric_line, i_ptr, i_size);

    submit_metric(metric_line, i_size);

    m3ApiReturn(i_size);
}

M3Result SuppressLookupFailure(M3Result i_result)
{
    if (i_result == m3Err_functionLookupFailed)
        return m3Err_none;
    else
        return i_result;
}

M3Result m3_LinkRuntimeExtension(IM3Module module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "submit_metric", "i(*i)", &m3_ext_submit_metric)));

_catch:
    return result;
}

static M3Result link_all(IM3Module module)
{
    M3Result res;
    res = m3_LinkSpecTest(module);
    if (res)
        return res;

    res = m3_LinkLibC(module);
    if (res)
        return res;

    res = m3_LinkRuntimeExtension(module);
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

void print_backtrace()
{
    IM3BacktraceInfo info = m3_GetBacktrace(runtime);
    if (!info) {
        return;
    }

    printk("wasm3: backtrace:");

    int frameCount = 0;
    IM3BacktraceFrame curr = info->frames;
    if (!curr)
            printk("found no frames");
    while (curr)
    {
        // printk("found frame function is -> %p", curr->function);
        printk("  %d: 0x%06x - %s!%s",
                frameCount, curr->moduleOffset,
                m3_GetModuleName (m3_GetFunctionModule(curr->function)),
                m3_GetFunctionName (curr->function)
        );
        curr = curr->next;
        frameCount++;
    }
    if (info->lastFrame == M3_BACKTRACE_TRUNCATED) {
        printk("\n  (truncated)");
    }
}
