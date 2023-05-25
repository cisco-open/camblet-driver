/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/slab.h>

#include "runtime.h"
#include "worker_thread.h"
#include "hashtable.h"

#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_libc.h"

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

wasm_vm *wasm_vm_new(int cpu)
{
    wasm_vm *vm = kmalloc(sizeof(wasm_vm), GFP_KERNEL);

    vm->cpu = cpu;

    vm->_env = m3_NewEnvironment();
    if (vm->_env == NULL)
    {
        kfree(vm);
        return NULL;
    }

    vm->_runtime = m3_NewRuntime(vm->_env, STACK_SIZE_BYTES, NULL);
    if (vm->_runtime == NULL)
    {
        m3_FreeEnvironment(vm->_env);
        kfree(vm);
        return NULL;
    }

    spin_lock_init(&vm->_lock);

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

wasm_vm *this_cpu_wasm_vm(void)
{
    int cpu = get_cpu();
    put_cpu();
    return vms[cpu];
}

wasm_vm *wasm_vm_for_cpu(unsigned cpu)
{
    if (cpu >= nr_cpu_ids) return NULL;
    return vms[cpu];
}

const char *wasm_vm_last_error(wasm_vm *vm)
{
    return vm->_runtime->error_message;
}

wasm_vm_result wasm_vm_new_per_cpu(void)
{
    int cpu = 0;
    for_each_possible_cpu(cpu)
    {
        printk("wasm: creating vm for cpu %d", cpu);
        vms[cpu] = wasm_vm_new(cpu);
    }
    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result wasm_vm_destroy_per_cpu(void)
{
    if (vms[0])
    {
        int cpu = 0;
        for_each_possible_cpu(cpu)
        {
            printk("wasm: destroying vm for cpu %d", cpu);
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

    pr_err("wasm: backtrace:");

    int frameCount = 0;
    IM3BacktraceFrame curr = info->frames;
    if (!curr)
        pr_err("found no frames");
    while (curr)
    {
        // printk("found frame function is -> %p", curr->function);
        pr_err("  %d: 0x%06x - %s!%s",
               frameCount, curr->moduleOffset,
               m3_GetModuleName(m3_GetFunctionModule(curr->function)),
               m3_GetFunctionName(curr->function));
        curr = curr->next;
        frameCount++;
    }
    if (info->lastFrame == M3_BACKTRACE_TRUNCATED)
    {
        pr_err("\n  (truncated)");
    }
}

wasm_vm_result wasm_vm_load_module(wasm_vm *vm, const char *name, unsigned char code[], unsigned code_size)
{
    M3Result result = m3Err_none;
    IM3Module module = NULL;

    u8 *wasm = kmalloc(code_size, GFP_ATOMIC);
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

    char *module_name = kmalloc(strlen(name), GFP_ATOMIC);
    strcpy(module_name, name);
    m3_SetModuleName(module, module_name);

    result = m3_link_all(module);
    if (result)
        goto on_error;

    if (wasm_bins_qty < MAX_MODULES)
    {
        wasm_bins[wasm_bins_qty++] = wasm;
    }

    return (wasm_vm_result){.data = {{.module = module}}, .err = NULL};

on_error:
    m3_FreeModule(module);
    if (wasm)
    {
        kfree(wasm);
        kfree(module_name);
    }

    return (wasm_vm_result){.err = result};
}

wasm_vm_result wasm_vm_call_direct_v(wasm_vm *vm, wasm_vm_function *func, va_list args)
{
    M3Result result = m3_CallVL(func, args);
    if (result)
    {
        wasm_vm_print_backtrace(vm);
        return (wasm_vm_result){.err = result};
    }

    int ret_count = m3_GetRetCount(func);
    if (ret_count == 0)
    {
        return (wasm_vm_result){.err = NULL};
    }

    static uint64_t valbuff[MAX_RETURN_VALUES] = {0};
    static const void *valptrs[MAX_RETURN_VALUES];
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
    wasm_vm_result vm_result;
    for(i = 0; i < ret_count; i++)
    {
        switch (m3_GetRetType(func, i))
        {
        case c_m3Type_i32:
            vm_result.data[i].i32 = *(i32 *)valptrs[i];
            break;
        case c_m3Type_i64:
            vm_result.data[i].i64 = *(i64 *)valptrs[i];
            break;
# if d_m3HasFloat
        case c_m3Type_f32:
            vm_result.data[i].f32 = *(f32 *)valptrs[i];
            break;
        case c_m3Type_f64:
            vm_result.data[i].f64 = *(f64 *)valptrs[i];
            break;
# endif
        default:
            return (wasm_vm_result){.err = "unknown return type"};
        }
    }
    vm_result.err = NULL;
    return vm_result;
}

wasm_vm_result wasm_vm_call_direct(wasm_vm *vm, wasm_vm_function *func, ...)
{
    va_list ap;
    va_start(ap, func);
    return wasm_vm_call_direct_v(vm, func, ap);
    va_end(ap);
}

wasm_vm_result wasm_vm_call(wasm_vm *vm, const char *module, const char *name, ...)
{
    wasm_vm_result result = wasm_vm_get_function(vm, module, name);
    if (result.err)
    {
        return result;
    }

    wasm_vm_function *func = result.data->function;

    va_list ap;
    va_start(ap, name);
    return wasm_vm_call_direct_v(vm, func, ap);
    va_end(ap);
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
        return (wasm_vm_result){.data[0].i32 = tagged.value.i32};
    case c_m3Type_i64:
        return (wasm_vm_result){.data[0].i64 = tagged.value.i64};
# if d_m3HasFloat
    case c_m3Type_f32:
        return (wasm_vm_result){.data[0].f32 = tagged.value.f32};
    case c_m3Type_f64:
        return (wasm_vm_result){.data[0].f64 = tagged.value.f64};
#endif
    default:
        return (wasm_vm_result){};
    }
}

wasm_vm_result wasm_vm_malloc(wasm_vm *vm, const char *module, unsigned size)
{
    return wasm_vm_call(vm, module, "malloc", size);
}

wasm_vm_result wasm_vm_free(wasm_vm *vm, const char *module, i32 ptr, unsigned size)
{
    return wasm_vm_call(vm, module, "free", ptr, size);
}

m3ApiRawFunction(m3_ext_table_add)
{
    m3ApiGetArg(i32,   key);

    m3ApiGetArgMem(void*,    i_ptr);
    m3ApiGetArg(wasm_size_t,  i_size);

    m3ApiCheckMem(i_ptr, i_size);

    add_to_module_hashtable(key, i_ptr, i_size);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_table_del)
{
    m3ApiGetArg(i32, key);

    delete_from_module_hashtable(key);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_table_get)
{
    m3ApiMultiValueReturnType (i32, ptr);
    m3ApiMultiValueReturnType (i32, len);
    m3ApiGetArg     (i32,     key);

    void* data_ptr = NULL;
    i32 data_len = 0;

    get_from_module_hashtable(_ctx->function->module->name, key, &data_ptr, &data_len);

    if (!data_ptr)
    {
        m3ApiMultiValueReturn(len, 0);
        m3ApiMultiValueReturn(ptr, 0);
        m3ApiSuccess();
    }

    m3ApiMultiValueReturn(len, (i32)data_len);
    m3ApiMultiValueReturn(ptr, (i32)data_ptr);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_table_keys)
{
    m3ApiMultiValueReturnType (i32, ptr);
    m3ApiMultiValueReturnType (i32, len);

    void* data_ptr;
    i32 data_len;

    keys_from_module_hashtable(_ctx->function->module->name, &data_ptr, &data_len);

    m3ApiMultiValueReturn(len, (i32)data_len);
    m3ApiMultiValueReturn(ptr, (i32)data_ptr);
    m3ApiSuccess();
}

m3ApiRawFunction(m3_ext_submit_metric)
{
    m3ApiReturnType (uint32_t);
    
    m3ApiGetArgMem  (void*,           i_ptr);
    m3ApiGetArg     (wasm_size_t,     i_size);

    m3ApiCheckMem(i_ptr, i_size);
    
    char *metric_line = (char *)kmalloc(i_size, GFP_ATOMIC);
    if (!metric_line)
    {
        pr_err("wasm: cannot allocate memory for metric_line");
        m3ApiReturn(-1);
    }

    memcpy(metric_line, i_ptr, i_size);

    submit_metric(metric_line, i_size);

    m3ApiReturn(i_size);
}

m3ApiRawFunction(m3_wasi_generic_environ_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (uint32_t *           , env)
    m3ApiGetArgMem   (char *               , env_buf)

    uint32_t ret = 0;
    // __wasi_size_t env_count, env_buf_size;

    // ret = __wasi_environ_sizes_get(&env_count, &env_buf_size);
    // if (ret != __WASI_ERRNO_SUCCESS) m3ApiReturn(ret);

    // m3ApiCheckMem(env,      env_count * sizeof(uint32_t));
    // m3ApiCheckMem(env_buf,  env_buf_size);

    // ret = __wasi_environ_get(env, env_buf);
    // if (ret != __WASI_ERRNO_SUCCESS) m3ApiReturn(ret);

    // for (u32 i = 0; i < env_count; ++i) {
    //     env[i] = m3ApiPtrToOffset (env[i]);
    // }

    m3ApiReturn(0);
}

m3ApiRawFunction(m3_wasi_generic_environ_sizes_get)
{
    m3ApiReturnType  (uint32_t)
    m3ApiGetArgMem   (uint32_t *      , env_count)
    m3ApiGetArgMem   (uint32_t *      , env_buf_size)

    m3ApiCheckMem(env_count,    sizeof(uint32_t));
    m3ApiCheckMem(env_buf_size, sizeof(uint32_t));

    *env_count = 0;
    *env_buf_size = 0;

    uint32_t ret = 0; //__wasi_environ_sizes_get(env_count, env_buf_size);

    m3ApiReturn(0);
}

m3ApiRawFunction(m3_wasi_generic_proc_exit)
{
    m3ApiGetArg   (i32, code)
    m3ApiSuccess();
}

M3Result SuppressLookupFailure(M3Result i_result)
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
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_get", "ii(i)", &m3_ext_table_get)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_keys", "ii()", &m3_ext_table_keys)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_add", "(i*i)", &m3_ext_table_add)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, env, "table_del", "(i)", &m3_ext_table_del)));

_catch:
    return result;
}

// Some Wasi mockings only for proxy-wasm
static M3Result m3_LinkWASIMocks(IM3Module module)
{
    M3Result result = m3Err_none;

    const char *wasi = "wasi_snapshot_preview1";

    _(SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "environ_get",       "i(**)", m3_wasi_generic_environ_get)));
    _(SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "environ_sizes_get", "i(**)", m3_wasi_generic_environ_sizes_get)));
    _(SuppressLookupFailure (m3_LinkRawFunction (module, wasi, "proc_exit",           "(i)", m3_wasi_generic_proc_exit)));

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

    res = m3_LinkWASIMocks(module);
    if (res)
        return res;

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

static void *print_module_symbols(IM3Module module, void * i_info)
{
    printk("wasm:   module = %s\n", module->name);
    int i;
    for (i = 0; i < module->numGlobals; i++)
    {
        printk("wasm:     global -> %s", module->globals[i].name);
    }
    for (i = 0; i < module->numFunctions; i++)
    {
        IM3Function f = & module->functions [i];

        bool isImported = f->import.moduleUtf8 || f->import.fieldUtf8;

        if (isImported)
            printk("wasm:     import -> %s.%s", f->import.moduleUtf8, f->names[0]);
    }
    for (i = 0; i < module->numFunctions; i++)
    {
        IM3Function f = &module->functions[i];

        if (f->export_name != NULL)
        {
            printk("wasm:     function -> %s(%d) -> %d", f->export_name, f->funcType->numArgs, f->funcType->numRets);
        }
    }

    return NULL;
}

void wasm_vm_dump_symbols(wasm_vm *vm)
{
    printk("wasm: vm for cpu = %d\n", vm->cpu);
    ForEachModule(vm->_runtime, print_module_symbols, NULL);
}

void wasm_vm_lock(wasm_vm *vm)
{
    spin_lock_irqsave(&vm->_lock, vm->_lock_flags);
}

void wasm_vm_unlock(wasm_vm *vm)
{
    spin_unlock_irqrestore(&vm->_lock, vm->_lock_flags);
}

wasm_vm_result wasm_vm_get_module(wasm_vm *vm, const char *name)
{
    wasm_vm_module *module = ForEachModule(vm->_runtime, (ModuleVisitor)v_FindModule, (void *)name);

    return (wasm_vm_result){.data = {{.module = module}}};
}

wasm_vm_result wasm_vm_get_function(wasm_vm *vm, const char *module, const char *name)
{
    IM3Function function = NULL;
    M3Result result = m3_FindFunctionInModule(&function, vm->_runtime, module, name);

    return (wasm_vm_result){.data = {{.function = function}}, .err = result};
}
