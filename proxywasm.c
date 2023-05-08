/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/hashtable.h>
#include <linux/xxhash.h>

#include "proxywasm.h"

#define HASH_SEED 98469223

typedef struct property_h_node {
    int key;
    char *value;
    struct hlist_node node;
} property_h_node;

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

    i32 tick_period;

    DECLARE_HASHTABLE(properties, 10);
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

    m3ApiReturn(WasmResult_Ok);
}

m3ApiRawFunction(proxy_set_tick_period_milliseconds)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, tick_period);

    proxywasm *proxywasm = _ctx->userdata;

    printk("wasm: calling proxy_set_tick_period_milliseconds %d", tick_period);

    proxywasm->tick_period = tick_period;

    m3ApiReturn(WasmResult_Ok);
}

m3ApiRawFunction(proxy_get_property)
{
    m3ApiReturnType(i32);

    m3ApiGetArgMem(char *, property_path_data);
    m3ApiGetArg(i32, property_path_size);

    m3ApiGetArgMem(char *, return_property_value_data);
    m3ApiGetArgMem(i32 *, return_property_value_size);

    proxywasm *proxywasm = _ctx->userdata;

    printk("wasm: calling proxy_get_property '%.*s'", property_path_size, property_path_data);

    m3ApiReturn(WasmResult_Ok);
}

static wasm_vm_result link_proxywasm_hostfunctions(proxywasm *proxywasm, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_log", "i(iii)", proxy_log, proxywasm)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_set_tick_period_milliseconds", "i(i)", proxy_set_tick_period_milliseconds, proxywasm)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_get_property", "i(iiii)", proxy_get_property, proxywasm)));

_catch:
    return (wasm_vm_result){.err = result};
}

wasm_vm_result init_proxywasm_for(wasm_vm *vm, const char* module)
{
    wasm_vm_result result;

    proxywasm *proxywasm = kmalloc(sizeof(proxywasm), GFP_KERNEL);
    proxywasm->proxy_on_memory_allocate = wasm_vm_get_function(vm, module, "proxy_on_memory_allocate");
    proxywasm->proxy_on_context_create = wasm_vm_get_function(vm, module, "proxy_on_context_create");
    proxywasm->proxy_on_vm_start = wasm_vm_get_function(vm, module, "proxy_on_vm_start");
    proxywasm->proxy_on_configure = wasm_vm_get_function(vm, module, "proxy_on_configure");
    proxywasm->vm = vm;

    hash_init(proxywasm->properties);

    result = link_proxywasm_hostfunctions(proxywasm, wasm_vm_get_module(vm, module));
    if (result.err)
    {
        kfree(proxywasm);
        return result;
    }

    i32 root_context_id = 0; // TODO

    result = wasm_vm_call_direct(vm, proxywasm->proxy_on_context_create, root_context_id, 0);
    if (result.err)
    {
        FATAL("proxy_on_context_create for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    result = wasm_vm_call_direct(vm, proxywasm->proxy_on_vm_start, root_context_id, 0);
    if (result.err)
    {
        FATAL("proxy_on_vm_start for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    i32 plugin_configuration_size = 0; // TODO

    result = wasm_vm_call_direct(vm, proxywasm->proxy_on_configure, root_context_id, plugin_configuration_size);
    if (result.err)
    {
        FATAL("proxy_on_configure for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    proxywasms[vm->cpu] = proxywasm;

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result proxy_on_new_connection(proxywasm *proxywasm, i32 context_id)
{
    return wasm_vm_call_direct(proxywasm->vm, proxywasm->proxy_on_new_connection, context_id);
}

void set_property(proxywasm *proxywasm, const char *key, const char *value)
{
    // Since linux hashtable always appends the new element to the bucket ignoring key collision altogether
    // we have to check whether an item with the key is already present in the map.
    // If it does we must handle that with raising an error.
    bool update = false;
    struct property_h_node *cur = NULL;
    struct property_h_node *bucket = NULL;
    unsigned long key_i = xxhash(key, strlen(key), HASH_SEED);

    hash_for_each_possible(proxywasm->properties, cur, node, key_i)
    {
        bucket = cur;
    }

    if (bucket)
    {
        printk("wasm: duplicate key (%s) found in hashmap, overwriting", key);
        kfree(bucket->value);
        update = true;
    }
    else
    {
        bucket = kmalloc(sizeof(struct property_h_node), GFP_KERNEL);
    }

    int value_len = strlen(value);
    bucket->key = key_i;
    bucket->value = (char*) kmalloc(value_len, GFP_KERNEL);
    memcpy(bucket->value, value, value_len);

    if (!update)
    {
        hash_add(proxywasm->properties, &bucket->node, key_i);
    }
}

enum WasmResult get_property(proxywasm *proxywasm, const char *key, const char *value)
{
    struct property_h_node *cur = NULL;
    struct property_h_node *temp = NULL;
    unsigned long key_i = xxhash(key, strlen(key), HASH_SEED);

    hash_for_each_possible(proxywasm->properties, cur, node, key_i)
    {
        temp = cur;
    }

    if (!temp)
    {
        return WasmResult_NotFound;
    }

    memcpy(value, temp->value, strlen(temp->value));

    return WasmResult_Ok;
}

