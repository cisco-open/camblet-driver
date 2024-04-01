/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/slab.h>
#include <linux/mm.h>

#include "wasm.h"
#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_libc.h"
#include "string.h"

typedef uint32_t wasm_ptr_t;
typedef uint32_t wasm_size_t;

const wasm_vm_result wasm_vm_ok = {0};

typedef struct wasm_vm
{
    struct mutex _lock;

    int cpu;

    IM3Environment _env;
    IM3Runtime _runtimes[MAX_MODULES_PER_VM];
    int _num_runtimes;

    u8 *wasm_bins[MAX_MODULES_PER_VM];

} wasm_vm;

static wasm_vm *vms[NR_CPUS];

static M3Result m3_link_all(IM3Module module);

wasm_vm *wasm_vm_new(int cpu)
{
    wasm_vm *vm = kzalloc(sizeof(wasm_vm), GFP_KERNEL);

    vm->cpu = cpu;

    vm->_env = m3_NewEnvironment();
    if (vm->_env == NULL)
    {
        kfree(vm);
        return NULL;
    }

    mutex_init(&vm->_lock);

    return vm;
}

static void *free_module_name(IM3Module module, void *i_info)
{
    kfree(module->name);
    module->name = "freeing";
    return NULL;
}

void wasm_vm_destroy(wasm_vm *vm)
{
    int i;
    for (i = 0; i < vm->_num_runtimes; i++)
    {
        IM3Runtime runtime = vm->_runtimes[i];
        ForEachModule(runtime, free_module_name, NULL);
        m3_FreeRuntime(runtime);
        kfree(vm->wasm_bins[i]);
    }
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
    if (cpu >= num_online_cpus())
    {
        pr_err("cpu[%d] is not online", cpu);
        return NULL;
    }
    return vms[cpu];
}

const char *wasm_vm_last_error(wasm_vm_module *module)
{
    return module->runtime->error_message;
}

wasm_vm_result wasm_vm_new_per_cpu(void)
{
    int cpu = 0;
    for_each_online_cpu(cpu)
    {
        pr_info("create vm # cpu[%d]", cpu);
        vms[cpu] = wasm_vm_new(cpu);
    }
    return wasm_vm_ok;
}

wasm_vm_result wasm_vm_destroy_per_cpu(void)
{
    if (vms[0])
    {
        int cpu = 0;
        for_each_online_cpu(cpu)
        {
            pr_info("destroy vm # cpu[%d]", cpu);
            wasm_vm_destroy(vms[cpu]);
        }
    }

    return wasm_vm_ok;
}

static void wasm_vm_print_backtrace(wasm_vm_function *func)
{
    IM3BacktraceInfo info = m3_GetBacktrace(func->module->runtime);
    if (!info)
    {
        return;
    }

    pr_err("backtrace:");

    int frameCount = 0;
    IM3BacktraceFrame curr = info->frames;
    if (!curr)
        pr_err("found no frames");
    while (curr)
    {
        // pr_info("found frame function is -> %p", curr->function);
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
    IM3Runtime runtime = NULL;

    if (vm->_num_runtimes == MAX_MODULES_PER_VM)
    {
        return (wasm_vm_result){.err = "too many modules loaded"};
    }

    u8 *wasm = kvmalloc(code_size, GFP_KERNEL);
    if (!wasm)
    {
        result = "cannot allocate memory for wasm binary";
        goto on_error;
    }

    memcpy(wasm, code, code_size);

    result = m3_ParseModule(vm->_env, &module, wasm, code_size);
    if (result)
    {
        goto on_error;
    }

    runtime = m3_NewRuntime(vm->_env, STACK_SIZE_BYTES, NULL);
    if (runtime == NULL)
    {
        result = "cannot allocate memory for wasm runtime";
        goto on_error;
    }

    result = m3_LoadModule(runtime, module);
    if (result)
    {
        goto on_error;
    }

    char *module_name = kstrdup(name, GFP_KERNEL);
    if (!module_name)
    {
        result = "could not allocate memory";
        goto on_error;
    }
    m3_SetModuleName(module, module_name);

    result = m3_link_all(module);
    if (result)
        goto on_error;

    vm->wasm_bins[vm->_num_runtimes] = wasm;
    vm->_runtimes[vm->_num_runtimes] = runtime;

    vm->_num_runtimes++;

    return (wasm_vm_result){.data = {{.module = module}}, .err = NULL};

on_error:
    m3_FreeModule(module);
    m3_FreeRuntime(runtime);
    kfree(wasm);
    kfree(module_name);

    return (wasm_vm_result){.err = result};
}

int wasm_vm_cpu(wasm_vm *vm)
{
    return vm->cpu;
}

wasm_vm_result wasm_vm_call_direct_v(wasm_vm *vm, wasm_vm_function *func, va_list args)
{
    M3Result result = m3_CallVL(func, args);
    if (result)
    {
        wasm_vm_print_backtrace(func);
        return (wasm_vm_result){.err = result};
    }

    int ret_count = m3_GetRetCount(func);
    if (ret_count == 0)
    {
        return wasm_vm_ok;
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
    for (i = 0; i < ret_count; i++)
    {
        switch (m3_GetRetType(func, i))
        {
        case c_m3Type_i32:
            vm_result.data[i].i32 = *(i32 *)valptrs[i];
            break;
        case c_m3Type_i64:
            vm_result.data[i].i64 = *(i64 *)valptrs[i];
            break;
#if d_m3HasFloat
        case c_m3Type_f32:
            vm_result.data[i].f32 = *(f32 *)valptrs[i];
            break;
        case c_m3Type_f64:
            vm_result.data[i].f64 = *(f64 *)valptrs[i];
            break;
#endif
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

uint8_t *wasm_vm_memory(wasm_vm_module *module)
{
    uint32_t len;
    if (!module->runtime->memory.mallocated)
    {
        return 0;
    }
    return m3_GetMemory(module->runtime, &len, 0);
}

wasm_vm_result wasm_vm_global(wasm_vm_module *module, const char *name)
{
    IM3Global g = m3_FindGlobal(module, name);

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
#if d_m3HasFloat
    case c_m3Type_f32:
        return (wasm_vm_result){.data[0].f32 = tagged.value.f32};
    case c_m3Type_f64:
        return (wasm_vm_result){.data[0].f64 = tagged.value.f64};
#endif
    default:
        return wasm_vm_ok;
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

m3ApiRawFunction(m3_wasi_generic_environ_get)
{
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(uint32_t *, env);
    m3ApiGetArgMem(char *, env_buf);

    m3ApiReturn(0);
}

m3ApiRawFunction(m3_wasi_generic_environ_sizes_get)
{
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(uint32_t *, env_count);
    m3ApiGetArgMem(uint32_t *, env_buf_size);

    m3ApiCheckMem(env_count, sizeof(uint32_t));
    m3ApiCheckMem(env_buf_size, sizeof(uint32_t));

    *env_count = 0;
    *env_buf_size = 0;

    m3ApiReturn(0);
}

m3ApiRawFunction(m3_wasi_generic_proc_exit)
{
    m3ApiGetArg(i32, code);
    m3ApiSuccess();
}

M3Result SuppressLookupFailure(M3Result i_result)
{
    if (i_result == m3Err_functionLookupFailed)
        return m3Err_none;
    else
        return i_result;
}

// Some Wasi mockings only for proxy-wasm
static M3Result m3_LinkWASIMocks(IM3Module module)
{
    M3Result result = m3Err_none;

    const char *wasi = "wasi_snapshot_preview1";

    _(SuppressLookupFailure(m3_LinkRawFunction(module, wasi, "environ_get", "i(**)", m3_wasi_generic_environ_get)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, wasi, "environ_sizes_get", "i(**)", m3_wasi_generic_environ_sizes_get)));
    _(SuppressLookupFailure(m3_LinkRawFunction(module, wasi, "proc_exit", "(i)", m3_wasi_generic_proc_exit)));

_catch:
    return result;
}

static M3Result m3_link_all(IM3Module module)
{
    M3Result res = NULL;
    res = m3_LinkLibC(module);
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

static void *print_module_symbols(IM3Module module, void *i_info)
{
    pr_debug("\tmodule = %s\n", module->name);
    int i;
    for (i = 0; i < module->numGlobals; i++)
    {
        pr_debug("\t\tglobal -> %s", module->globals[i].name);
    }
    for (i = 0; i < module->numFunctions; i++)
    {
        IM3Function f = &module->functions[i];

        bool isImported = f->import.moduleUtf8 || f->import.fieldUtf8;

        if (isImported)
            pr_debug("\t\timport -> %s.%s", f->import.moduleUtf8, f->names[0]);
    }
    for (i = 0; i < module->numFunctions; i++)
    {
        IM3Function f = &module->functions[i];

        if (f->export_name != NULL)
        {
            pr_debug("\t\tfunction -> %s(%d) -> %d", f->export_name, f->funcType->numArgs, f->funcType->numRets);
        }
    }

    return NULL;
}

void wasm_vm_dump_symbols(wasm_vm *vm)
{
    pr_debug("vm # cpu[%d]", vm->cpu);
    int i;
    for (i = 0; i < vm->_num_runtimes; i++)
        ForEachModule(vm->_runtimes[i], print_module_symbols, NULL);
}

void wasm_vm_lock(wasm_vm *vm)
{
    mutex_lock(&vm->_lock);
}

void wasm_vm_unlock(wasm_vm *vm)
{
    mutex_unlock(&vm->_lock);
}

wasm_vm_result wasm_vm_get_module(wasm_vm *vm, const char *name)
{
    wasm_vm_module *module = NULL;
    int i;
    for (i = 0; i < vm->_num_runtimes; i++)
    {
        module = ForEachModule(vm->_runtimes[i], (ModuleVisitor)v_FindModule, (void *)name);
        if (module)
            break;
    }

    return (wasm_vm_result){.data = {{.module = module}}};
}

wasm_vm_result wasm_vm_get_function(wasm_vm *vm, const char *module, const char *name)
{
    IM3Function function = NULL;
    M3Result result = m3Err_functionLookupFailed;

    int i;
    for (i = 0; i < vm->_num_runtimes; i++)
    {
        result = m3_FindFunctionInModule(&function, vm->_runtimes[i], module, name);

        if (function)
            break;
    }

    return (wasm_vm_result){.data = {{.function = function}}, .err = result};
}
