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

typedef struct property_h_node {
    char key[256];
    int key_len;
    char *value;
    int value_len;
    struct hlist_node node;
} property_h_node;

static atomic_t context_id = ATOMIC_INIT(0);

static int new_context_id(void) {
    return atomic_inc_return(&context_id);
}

typedef struct proxywasm_context {
    int id;
} proxywasm_context;

DEFINE_HASHTABLE(properties, 6);

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

    // the current context under processing
    proxywasm_context *current_context;

    // DECLARE_HASHTABLE(properties, 6);
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

    m3ApiCheckMem(property_path_data, property_path_size);

    m3ApiGetArgMem(i32 *, return_property_value_data);
    m3ApiGetArgMem(i32 *, return_property_value_size);

    proxywasm *proxywasm = _ctx->userdata;

    char *value = NULL;
    int value_len;
    printk("wasm: calling proxy_get_property '%.*s' (%d) return values -> %p %p", property_path_size, property_path_data, property_path_size, return_property_value_data, return_property_value_size);

    get_property(proxywasm, property_path_data, property_path_size, &value, &value_len);

    if (value_len > 0)
    {
        wasm_vm_result result = proxy_on_memory_allocate(proxywasm, value_len);
        if (result.err)
        {
            FATAL("proxywasm proxy_on_memory_allocate error: %s", result.err);
            return m3Err_mallocFailed;
        }

        printk("wasm: proxy_on_memory_allocate returned %d, value points to %p, *return_property_value_data -> %d", result.data->i32, value, *return_property_value_data);

        int wasm_ptr = result.data->i32;

        void *value_ptr = m3ApiOffsetToPtr(wasm_ptr);
        memcpy(value_ptr, value, value_len);

        *return_property_value_data = wasm_ptr;
        *return_property_value_size = value_len;

        printk("wasm: proxy_get_property ready, value_len: %d, return_property_value_data -> %d", value_len, *return_property_value_data);

        m3ApiReturn(WasmResult_Ok);
    }

    printk("wasm: proxy_get_property WasmResult_NotFound");
    m3ApiReturn(WasmResult_NotFound);
}

m3ApiRawFunction(proxy_get_buffer_bytes)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, buffer_type);
    m3ApiGetArg(i32, offset);
    m3ApiGetArg(i32, max_size);

    m3ApiGetArgMem(char *, return_buffer_data);
    m3ApiGetArgMem(i32 *, return_buffer_size);

    proxywasm *proxywasm = _ctx->userdata;

    char *value = NULL;
    int value_len = 0;
    printk("wasm: calling proxy_get_buffer buffer_type '%d' (offset: %d, max_size: %d)", buffer_type, offset, max_size);

    get_buffer_bytes(proxywasm, buffer_type, offset, max_size, &value, &value_len);

    if (value_len > 0)
    {
        wasm_vm_result result = proxy_on_memory_allocate(proxywasm, value_len);
        if (result.err)
        {
            FATAL("proxywasm proxy_on_memory_allocate error: %s", result.err);
            return m3Err_mallocFailed;
        }

        printk("wasm: proxy_on_memory_allocate returned %d, value points to %p, *return_buffer_data -> %d", result.data->i32, value, *return_buffer_data);

        int wasm_ptr = result.data->i32;

        void *value_ptr = m3ApiOffsetToPtr(wasm_ptr);
        memcpy(value_ptr, value, value_len);

        *return_buffer_data = wasm_ptr;
        *return_buffer_size = value_len;

        printk("wasm: get_buffer_bytes ready, value_len: %d, return_buffer_data -> %d value %d", value_len, *return_buffer_data, *(u32*)value_ptr);

        m3ApiReturn(WasmResult_Ok);
    }

    printk("wasm: get_buffer_bytes WasmResult_NotFound");
    m3ApiReturn(WasmResult_NotFound);
}

static wasm_vm_result link_proxywasm_hostfunctions(proxywasm *proxywasm, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_log", "i(i*i)", proxy_log, proxywasm)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_set_tick_period_milliseconds", "i(i)", proxy_set_tick_period_milliseconds, proxywasm)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_get_property", "i(*i**)", proxy_get_property, proxywasm)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_get_buffer_bytes", "i(iii**)", proxy_get_buffer_bytes, proxywasm)));

_catch:
    return (wasm_vm_result){.err = result};
}

void set_property_v(proxywasm *proxywasm, const char *value, const int value_len, ...)
{
    char path[256];
    int path_len = 0;

    va_list ap;
    va_start(ap, value_len);
    char *part = NULL;
    while ((part = va_arg(ap, char*)) != NULL)
    {
        int len = strlen(part);
        memcpy(path + path_len, part, len);
        path_len += len + 1;
        path[path_len] = 0;
    }
    va_end(ap);

    set_property(proxywasm, path, path_len - 1, value, value_len);
}

void print_property_key(const char *func, const char *key, int key_len)
{
    char buf[256] = {0};
    while (key_len-- > 0)
    {
        char c = *(key + key_len);
        if (c == 0)
            c = '.';
        buf[key_len] = c;
    }
    printk("wasm: %s key: %s", func, buf);
}

wasm_vm_result init_proxywasm_for(wasm_vm *vm, const char* module)
{
    wasm_vm_result result;

    proxywasm *proxywasm = kmalloc(sizeof(proxywasm), GFP_KERNEL);
    proxywasm->proxy_on_memory_allocate = wasm_vm_get_function(vm, module, "malloc"); // ???? proxy_on_memory_allocate?
    proxywasm->proxy_on_context_create = wasm_vm_get_function(vm, module, "proxy_on_context_create");
    proxywasm->proxy_on_new_connection = wasm_vm_get_function(vm, module, "proxy_on_new_connection");
    proxywasm->proxy_on_vm_start = wasm_vm_get_function(vm, module, "proxy_on_vm_start");
    proxywasm->proxy_on_configure = wasm_vm_get_function(vm, module, "proxy_on_configure");
    proxywasm->proxy_on_downstream_data = wasm_vm_get_function(vm, module, "proxy_on_downstream_data");
    proxywasm->vm = vm;

    // printk("wasm: ARRAY_SIZE %d", ARRAY_SIZE(proxywasm->properties));

    // hash_init((proxywasm->properties));

    {
        char empty_map[] = {0,0,0,0};
        u64 listener_direction = ListenerDirectionInbound;
        set_property_v(proxywasm, "lima", strlen("lima"), "node", "id", NULL);
        set_property_v(proxywasm, "catalog-v1-6578575465-lz5h2", strlen("catalog-v1-6578575465-lz5h2"), "node", "metadata", "NAME", NULL);
        set_property_v(proxywasm, "kube-system", strlen("kube-system"), "node", "metadata", "NAMESPACE", NULL);
        set_property_v(proxywasm, "blade-runner", strlen( "blade-runner"), "node", "metadata", "OWNER", NULL);
        set_property_v(proxywasm, "joska", strlen("joska"), "node", "metadata", "WORKLOAD_NAME", NULL);
        set_property_v(proxywasm, "1.13.5", strlen("1.13.5"), "node", "metadata", "ISTIO_VERSION", NULL);
        set_property_v(proxywasm, "mesh1", strlen("mesh1"), "node", "metadata", "MESH_ID", NULL);
        set_property_v(proxywasm, "cluster1", strlen("cluster1"), "node", "metadata", "CLUSTER_ID", NULL);
        set_property_v(proxywasm, empty_map, sizeof(empty_map), "node", "metadata", "LABELS", NULL);
        set_property_v(proxywasm, empty_map, sizeof(empty_map), "node", "metadata", "PLATFORM_METADATA", NULL);
        set_property_v(proxywasm, "catalog", strlen("catalog"), "node", "metadata", "APP_CONTAINERS", NULL);
        set_property_v(proxywasm, "10.20.160.34,fe80::84cb:9eff:feb7:941b", strlen("10.20.160.34,fe80::84cb:9eff:feb7:941b"), "node", "metadata", "INSTANCE_IPS", NULL);
        set_property_v(proxywasm, (char*)&listener_direction, sizeof(listener_direction), "listener_direction", NULL);
    }

    result = link_proxywasm_hostfunctions(proxywasm, wasm_vm_get_module(vm, module));
    if (result.err)
    {
        kfree(proxywasm);
        return result;
    }

    i32 root_context_id = new_context_id();
    printk("wasm: root_context_id %d", root_context_id);

    // Create the root context
    result = proxy_on_context_create(proxywasm, root_context_id, 0);
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

    // Create a new non-root context
    i32 context_id = new_context_id();
    printk("wasm: root_context_id %d, context_id: %d", root_context_id, context_id);

    result = proxy_on_context_create(proxywasm, context_id, root_context_id);
    if (result.err)
    {
        FATAL("proxy_on_context_create for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    printk("wasm: proxy_on_context_create result %d", result.data->i32);

    result = proxy_on_new_connection(proxywasm, context_id);
    if (result.err)
    {
        FATAL("proxy_on_new_connection for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    printk("wasm: proxy_on_new_connection result %d", result.data->i32);

    result = proxy_on_downstream_data(proxywasm, context_id, 128, false);
    if (result.err)
    {
        FATAL("proxy_on_downstream_data for module %s failed: %s", module, result.err)
        kfree(proxywasm);
        return result;
    }

    proxywasms[vm->cpu] = proxywasm;

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result proxy_on_context_create(proxywasm *p, i32 context_id, i32 root_context_id)
{
    return wasm_vm_call_direct(p->vm, p->proxy_on_context_create, context_id, root_context_id);
}

wasm_vm_result proxy_on_new_connection(proxywasm *p, i32 context_id)
{
    return wasm_vm_call_direct(p->vm, p->proxy_on_new_connection, context_id);
}

wasm_vm_result proxy_on_downstream_data(proxywasm *p, i32 context_id, i32 data_size, i32 end_of_stream)
{
    return wasm_vm_call_direct(p->vm, p->proxy_on_downstream_data, context_id, data_size, end_of_stream);
}

void set_property(proxywasm *p, const char *key, int key_len, const char *value, int value_len)
{
    struct property_h_node *cur, *node = kmalloc(sizeof(property_h_node), GFP_KERNEL);
    unsigned long key_i = xxhash(key, key_len, 0);
    print_property_key("set_property", key, key_len);
    printk("wasm: set_property key hash %lu, key len: %d", key_i, key_len);

    node->key_len = key_len;
    memcpy(node->key, key, key_len);
    node->value_len = value_len;
    node->value = (char*) kmalloc(value_len, GFP_KERNEL);
    memcpy(node->value, value, value_len);

    printk("wasm: adding new bucket to hashtable");
    hash_add(properties, &node->node, key_i);

    // printk("wasm: listing all possible entries under key %lu", key_i);
    // hash_for_each_possible(proxywasm->properties, cur, node, key_i)
    //     pr_info("wasm:   match for key %lu: data = '%.*s'\n", key_i, cur->value_len, cur->value);
}

void get_property(proxywasm *proxywasm, const char *key, int key_len, char **value, int *value_len)
{
    struct property_h_node *cur = NULL;
    struct property_h_node *temp = NULL;
    unsigned long key_i = xxhash(key, key_len, 0);
    print_property_key("get_property", key, key_len);
    printk("wasm: key hash %lu, key len: %d key: '%.*s'", key_i, key_len, key_len, key); 

    hash_for_each_possible(properties, cur, node, key_i)
    {
        if (cur->key_len == key_len && memcmp(cur->key, key, key_len) == 0)
        {
            temp = cur;
            break;
        }
    }

    if (!temp)
    {
        printk("wasm: '%.*s' key not found", key_len, key);
        return;
    }

    printk("wasm: '%.*s' key found, value: %.*s", key_len, key, temp->value_len, temp->value);

    *value = temp->value;
    *value_len = temp->value_len;
}

u32 magic_number = 1025705063;

void get_buffer_bytes(proxywasm *proxywasm, BufferType buffer_type, i32 offset, i32 max_size, char **value, i32 *value_len)
{
    printk("wasm: get_buffer_bytes BufferType: %d, offset: %d, max_size: %d", buffer_type, offset, max_size);

    *value = (char *)&magic_number;
    *value_len = sizeof(magic_number);
}