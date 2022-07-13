#include <linux/slab.h>

#include "runtime.h"
#include "worker_thread.h"
#include "hashtable.h"

#include "wasm3/source/wasm3.h"
#include "wasm3/source/m3_env.h"
#include "wasm3/source/m3_api_libc.h"
#include "wasm3/source/m3_exception.h"

#define PRIi32 "i"
#define PRIi64 "lli"

#define MAX_MODULES 64
#define STACK_SIZE_BYTES 256 * 1024

typedef uint32_t wasm_ptr_t;
typedef uint32_t wasm_size_t;

static u8 *wasm_bins[MAX_MODULES];
static int wasm_bins_qty = 0;

static wasm_vm *vms[NR_CPUS];

static M3Result m3_link_all(IM3Module module);

wasm_vm *wasm_vm_new(unsigned stack)
{
    wasm_vm *vm = kmalloc(sizeof(wasm_vm), GFP_KERNEL);

    vm->_env = m3_NewEnvironment();
    if (vm->_env == NULL)
    {
        kfree(vm);
        return NULL;
    }

    vm->_runtime = m3_NewRuntime(vm->_env, stack, NULL);
    if (vm->_runtime == NULL)
    {
        m3_FreeEnvironment(vm->_env);
        kfree(vm);
        return NULL;
    }

    return vm;
}

static void *free_module_name(IM3Module module, void * i_info)
{
    kfree(module->name);
    module->name = "freeing";
    return NULL;
}

void wasm_vm_destroy(wasm_vm *vm)
{
    ForEachModule(vm->_runtime, free_module_name, NULL);
    m3_FreeRuntime(vm->_runtime);
    m3_FreeEnvironment(vm->_env);
    kfree(vm);
}

wasm_vm *current_wasm_vm(void)
{
    return vms[smp_processor_id()];
}

wasm_vm *wasm_vm_for_cpu(unsigned cpu)
{
    if (cpu >= nr_cpu_ids) return NULL;
    return vms[cpu];
}

wasm_vm_result wasm_vm_new_per_cpu(void)
{
    int cpu = 0;
    for_each_possible_cpu(cpu)
    {
        printk("wasm3: creating vm for cpu %d", cpu);
        vms[cpu] = wasm_vm_new(STACK_SIZE_BYTES);
    }
    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result wasm_vm_destroy_per_cpu(void)
{
    if (vms)
    {
        int cpu = 0;
        for_each_possible_cpu(cpu)
        {
            printk("wasm3: destroying vm for cpu %d", cpu);
            wasm_vm_destroy(vms[cpu]);
        }

        int i;
        for (i = 0; i < wasm_bins_qty; i++)
        {
            kfree(wasm_bins[i]);
        }
    }

    return (wasm_vm_result){.err = NULL};
}

static void wasm_vm_print_backtrace(wasm_vm *vm)
{
    IM3BacktraceInfo info = m3_GetBacktrace(vm->_runtime);
    if (!info)
    {
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
               m3_GetModuleName(m3_GetFunctionModule(curr->function)),
               m3_GetFunctionName(curr->function));
        curr = curr->next;
        frameCount++;
    }
    if (info->lastFrame == M3_BACKTRACE_TRUNCATED)
    {
        printk("\n  (truncated)");
    }
}

wasm_vm_result wasm_vm_load_module(wasm_vm *vm, const char *name, unsigned char code[], unsigned code_size)
{
    M3Result result = m3Err_none;
    IM3Module module = NULL;

    u8 *wasm = kmalloc(code_size, GFP_KERNEL);
    if (!wasm)
    {
        result = "cannot allocate memory for wasm binary";
        goto on_error;
    }

    memcpy(wasm, code, code_size);

    result = m3_ParseModule(vm->_env, &module, wasm, code_size);
    if (result)
        goto on_error;

    result = m3_LoadModule(vm->_runtime, module);
    if (result)
        goto on_error;

    char *module_name = kmalloc(strlen(name), GFP_KERNEL);
    strcpy(module_name, name);
    m3_SetModuleName(module, module_name);

    result = m3_link_all(module);
    if (result)
        goto on_error;

    if (wasm_bins_qty < MAX_MODULES)
    {
        wasm_bins[wasm_bins_qty++] = wasm;
    }

    return (wasm_vm_result){.err = NULL};

on_error:
    m3_FreeModule(module);
    if (wasm)
    {
        kfree(wasm);
        kfree(module_name);
    }

    return (wasm_vm_result){.err = result};
}

wasm_vm_result wasm_vm_call(wasm_vm *vm, const char *name, ...)
{
    M3Result result = m3Err_none;
    IM3Function func = NULL;

    result = m3_FindFunction(&func, vm->_runtime, name);
    if (result)
        return (wasm_vm_result){.err = result};

    int ret_count = m3_GetRetCount(func);

    va_list ap;
    va_start(ap, func);
    result = m3_CallVL(func, ap);
    va_end(ap);

    if (result)
    {
        wasm_vm_print_backtrace(vm);
        return (wasm_vm_result){.err = result};
    }

    if (ret_count == 0)
    {
        return (wasm_vm_result){.err = NULL};
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
        return (wasm_vm_result){.err = "failed to get results for call"};
    }

    switch (m3_GetRetType(func, 0))
    {
    case c_m3Type_i32:
        return (wasm_vm_result){.i32 = *(i32 *)valptrs[0], .err = NULL};
    case c_m3Type_i64:
        return (wasm_vm_result){.i64 = *(i64 *)valptrs[0], .err = NULL};
# if d_m3HasFloat
    case c_m3Type_f32:
        return (wasm_vm_result){.f32 = *(f32 *)valptrs[0], .err = NULL};
    case c_m3Type_f64:
        return (wasm_vm_result){.f64 = *(f64 *)valptrs[0], .err = NULL};
# endif
    default:
        return (wasm_vm_result){.err = "unknown return type"};
    }
}

uint8_t *wasm_vm_memory(wasm_vm *vm)
{
    uint32_t len;
    if (!vm->_runtime->memory.mallocated)
    {
        return 0;
    }
    return m3_GetMemory(vm->_runtime, &len, 0);
}

wasm_vm_result wasm_vm_global(wasm_vm *vm, const char *name)
{
    IM3Global g = m3_FindGlobal(vm->_runtime->modules, name);

    M3TaggedValue tagged;
    M3Result result = m3_GetGlobal(g, &tagged);
    if (result)
        return (wasm_vm_result){.err = result};

    switch (tagged.type)
    {
    case c_m3Type_i32:
        return (wasm_vm_result){.i32 = tagged.value.i32};
    case c_m3Type_i64:
        return (wasm_vm_result){.i64 = tagged.value.i64};
# if d_m3HasFloat
    case c_m3Type_f32:
        return (wasm_vm_result){.f32 = tagged.value.f32};
    case c_m3Type_f64:
        return (wasm_vm_result){.f64 = tagged.value.f64};
#endif
    default:
        return (wasm_vm_result){};
    }
}

wasm_vm_result wasm_vm_malloc(wasm_vm *vm, unsigned size)
{
    return wasm_vm_call(vm, "malloc", size);
}

wasm_vm_result wasm_vm_free(wasm_vm *vm, i32 ptr, unsigned size)
{
    return wasm_vm_call(vm, "free", ptr, size);
}

m3ApiRawFunction(m3_ext_table_add)
{
    m3ApiGetArg(i32,   key)

    m3ApiGetArgMem(void*,    i_ptr)
    m3ApiGetArg(wasm_size_t,  i_size)

    m3ApiCheckMem(i_ptr, i_size);

    add_to_module_hashtable(key, i_ptr, i_size);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_table_del)
{
    m3ApiGetArg(i32, key)

    delete_from_module_hashtable(key);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_table_get)
{
    m3ApiReturnType (i64)
    m3ApiGetArg     (i32,     key)

    void* data_ptr = NULL;
    i32 data_len = 0;

    get_from_module_hashtable(key, &data_ptr, &data_len);

    if (!data_ptr)
    {
        m3ApiReturn(0);
    }

    i64 res = ((i64)data_ptr << 32) | (i64) data_len;
    m3ApiReturn(res);
}

m3ApiRawFunction(m3_ext_table_keys)
{
    m3ApiReturnType (i64)

    void* data_ptr;
    i32 data_len;

    keys_from_module_hashtable(&data_ptr, &data_len);
    i64 res = ((i64)data_ptr << 32) | (i64) data_len;
    m3ApiReturn(res);
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
        printk("wasm3: cannot allocate memory for metric_line");
        m3ApiReturn(-1);
    }

    memcpy(metric_line, i_ptr, i_size);

    submit_metric(metric_line, i_size);

    m3ApiReturn(i_size);
}

static M3Result SuppressLookupFailure(M3Result i_result)
{
    if (i_result == m3Err_functionLookupFailed)
        return m3Err_none;
    else
        return i_result;
}

static M3Result m3_LinkRuntimeExtension(IM3Module module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "submit_metric", "i(*i)", &m3_ext_submit_metric)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_get", "I(i)", &m3_ext_table_get)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_keys", "I()", &m3_ext_table_keys)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_add", "(i*i)", &m3_ext_table_add)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_del", "(i)", &m3_ext_table_del)));

_catch:
    return result;
}

static M3Result m3_link_all(IM3Module module)
{
    M3Result res = NULL;
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
