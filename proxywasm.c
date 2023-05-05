/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include "proxywasm.h"

typedef struct proxywasm
{
    wasm_vm *vm;
	// Memory management
    wasm_vm_function *proxy_on_memory_allocate;
    // Module lifecycle
    wasm_vm_function *proxy_on_context_create;
    wasm_vm_function *proxy_on_done;
    wasm_vm_function *proxy_on_log;
    wasm_vm_function *proxy_on_delete;
    // Configuration
    wasm_vm_function *proxy_on_vm_start;
    wasm_vm_function *proxy_on_configure;
    // Timers
    wasm_vm_function *proxy_on_tick;
    // TCP/UDP/QUIC stream (L4) extensions
    wasm_vm_function *proxy_on_new_connection;
    wasm_vm_function *proxy_on_downstream_data;
    wasm_vm_function *proxy_on_downstream_close;
    wasm_vm_function *proxy_on_upstream_data;
    wasm_vm_function *proxy_on_upstream_close;    
} proxywasm;

static proxywasm *proxywasms[NR_CPUS] = {0};

wasm_vm_result proxy_on_memory_allocate(proxywasm *proxywasm, i32 size)
{
    return wasm_vm_call_direct(proxywasm->vm, proxywasm->proxy_on_memory_allocate, size);
}

proxywasm* this_cpu_proxywasm(void)
{
    int cpu = get_cpu();
    put_cpu();
    return proxywasms[cpu];
}

m3ApiRawFunction(proxy_log)
{
    m3ApiReturnType (i32)

    m3ApiGetArg(i32, log_level);
    m3ApiGetArgMem(char *, message_data);
    m3ApiGetArg(i32, message_size);

    m3ApiCheckMem(message_data, message_size);

    printk("proxywasm: [%d] %.*s", log_level, message_size, message_data);

    m3ApiSuccess();
}

m3ApiRawFunction(proxy_set_tick_period_milliseconds)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, tick_period);

    proxywasm *proxywasm = (proxywasm*) _ctx->userdata;

    printk("wasm: calling proxy_set_tick_period_milliseconds %d", builtin_id);

    proxywasm->tick_period = tick_period;

    m3ApiReturn(1);
}

static wasm_vm_result link_proxywasm_builtins(proxywasm *proxywasm, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_log", "i(iii)", &proxy_log, proxywasm)));

_catch:
    return (wasm_vm_result){.err = result};
}

wasm_vm_result init_proxywasm_for(wasm_vm *vm, const char* module)
{
    proxywasm *proxywasm = kmalloc(sizeof(proxywasm), GFP_KERNEL);
    proxywasm->proxy_on_memory_allocate = wasm_vm_get_function(vm, module, "proxy_on_memory_allocate");
    proxywasm->proxy_on_context_create = wasm_vm_get_function(vm, module, "proxy_on_context_create");
    proxywasm->proxy_on_vm_start = wasm_vm_get_function(vm, module, "proxy_on_vm_start");
    proxywasm->proxy_on_configure = wasm_vm_get_function(vm, module, "proxy_on_configure");
    proxywasm->vm = vm;

    wasm_vm_result result = wasm_vm_call_direct(vm, proxywasm->proxy_on_context_create);
    if (result.err)
    {
        kfree(proxywasm);
        return result;
    }

    result = wasm_vm_call_direct(vm, opa->json_dump, result.data->i32);
    if (result.err)
    {
        kfree(opa);
        return result;
    }

    uint8_t *memory = wasm_vm_memory(vm);
    i32 builtinsJson = result.data->i32;

    // parse and link
    char *builtins = memory + builtinsJson;
    if (parse_opa_builtins(opa, builtins) > 0)
    {
        result = link_proxywasm_builtins(opa, wasm_vm_get_module(vm, OPA_MODULE));
        if (result.err)
        {
            kfree(opa->builtins);
            kfree(opa);
            return result;
        }
    }

    opa_free(opa, builtinsJson);

    opas[vm->cpu] = opa;

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result opa_eval(proxywasm *proxywasm, i32 inputAddr, i32 inputLen)
{
    i32 entrypoint = 0;
    i32 dataAddr = 0;
    i32 heapAddr = 0;
    i32 format = 0;

    return wasm_vm_call_direct(proxywasm->vm, opa->eval, 0, entrypoint, dataAddr, inputAddr, inputLen, heapAddr, format);
}
