/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/uaccess.h>
#include <linux/hashtable.h>
#include <linux/xxhash.h>

#include "buffer.h"
#include "proxywasm.h"

// We need to use dynamic hashtables, so we have to hack a bit around hashing macros:
#define HASHTABLE_BITS 4

#define hash_add(hashtable, node, key, bits) \
    hlist_add_head(node, &hashtable[hash_min(key, bits)])

#define hash_for_each_possible(name, obj, member, key, bits) \
    hlist_for_each_entry(obj, &name[hash_min(key, bits)], member)

#define FOR_ALL_FILTERS(CALL)                                                          \
    wasm_vm_result result;                                                             \
    proxywasm_filter *f;                                                               \
    for (f = p->filters; f != NULL; f = f->next)                                       \
    {                                                                                  \
        printk("nasp: calling %s " #CALL, f->name);                                    \
        result = CALL;                                                                 \
        if (result.err != NULL)                                                        \
        {                                                                              \
            pr_err("nasp: calling %s " #CALL " error: %s\n", f->name, result.err);     \
            return result;                                                             \
        }                                                                              \
        printk("nasp: result of calling %s " #CALL ": %d", f->name, result.data->i32); \
    }                                                                                  \
    return result;

typedef struct property_h_node
{
    char key[256];
    int key_len;
    char *value;
    int value_len;
    struct hlist_node node;
} property_h_node;

static atomic_t context_id = ATOMIC_INIT(0);

static int new_context_id(void)
{
    return atomic_inc_return(&context_id);
}

typedef struct proxywasm_context
{
    int id;

    i32 tick_period;

    // DECLARE_HASHTABLE(properties, 6);
    struct hlist_head *properties;

    proxywasm_context *parent;

    // plaintext proxywasm buffers
    buffer_t *upstream_buffer;
    buffer_t *downstream_buffer;
} proxywasm_context;

static proxywasm_context *new_proxywasm_context(proxywasm_context *parent, buffer_t *upstream_buffer, buffer_t *downstream_buffer)
{
    proxywasm_context *context = kzalloc(sizeof(struct proxywasm_context), GFP_KERNEL);

    context->properties = kzalloc((1 << HASHTABLE_BITS) * sizeof(struct hlist_head), GFP_KERNEL);
    __hash_init(context->properties, 1 << HASHTABLE_BITS);

    context->id = new_context_id();
    context->parent = parent;

    context->upstream_buffer = upstream_buffer;
    context->downstream_buffer = downstream_buffer;

    return context;
}

void free_proxywasm_context(proxywasm_context *context)
{
    kfree(context->properties);
    kfree(context);
}

typedef struct proxywasm_filter
{
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
    wasm_vm_function *proxy_on_downstream_connection_close;
    wasm_vm_function *proxy_on_upstream_data;
    wasm_vm_function *proxy_on_upstream_connection_close;

    proxywasm_filter *next;

    proxywasm *proxywasm;

    char name[64];

} proxywasm_filter;

typedef struct proxywasm
{
    wasm_vm *vm;

    proxywasm_filter *filters;

    proxywasm_context *root_context;

    // the current context under processing
    proxywasm_context *current_context;
} proxywasm;

static proxywasm *proxywasms[NR_CPUS] = {0};

wasm_vm_result proxy_on_memory_allocate(proxywasm_filter *filter, i32 size)
{
    return wasm_vm_call_direct(filter->proxywasm->vm, filter->proxy_on_memory_allocate, size);
}

proxywasm *proxywasm_for_vm(wasm_vm *vm)
{
    return proxywasms[wasm_vm_cpu(vm)];
}

proxywasm *this_cpu_proxywasm(void)
{
    int cpu = get_cpu();
    put_cpu();
    return proxywasms[cpu];
}

void proxywasm_set_context(proxywasm *p, proxywasm_context *context)
{
    p->current_context = context;
}

void proxywasm_lock(proxywasm *p, proxywasm_context *c)
{
    wasm_vm_lock(p->vm);
    proxywasm_set_context(p, c);
}

void proxywasm_unlock(proxywasm *p)
{
    wasm_vm_unlock(p->vm);
}

proxywasm_context *proxywasm_get_context(proxywasm *p)
{
    return p->current_context;
}

m3ApiRawFunction(proxy_log)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, log_level);
    m3ApiGetArgMem(char *, message_data);
    m3ApiGetArg(i32, message_size);

    m3ApiCheckMem(message_data, message_size);

    printk("nasp: proxywasm [%s] [%d] %.*s", current->comm, log_level, message_size, message_data);

    m3ApiReturn(WasmResult_Ok);
}

m3ApiRawFunction(proxy_set_tick_period_milliseconds)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, tick_period);

    proxywasm_filter *filter = _ctx->userdata;

    printk("nasp: calling proxy_set_tick_period_milliseconds %d", tick_period);

    filter->proxywasm->current_context->tick_period = tick_period;

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

    proxywasm_filter *filter = _ctx->userdata;

    char *value = NULL;
    int value_len;
    // printk("nasp: calling proxy_get_property in %s '%.*s' (%d) return values -> %p %p", filter->name, property_path_size, property_path_data, property_path_size, return_property_value_data, return_property_value_size);

    get_property(filter->proxywasm->current_context, property_path_data, property_path_size, &value, &value_len);

    if (value_len > 0)
    {
        wasm_vm_result result = proxy_on_memory_allocate(filter, value_len);
        if (result.err)
        {
            FATAL("proxywasm proxy_on_memory_allocate error: %s", result.err);
            return m3Err_mallocFailed;
        }

        // printk("nasp: proxy_on_memory_allocate returned %d, value points to %p, *return_property_value_data -> %d", result.data->i32, value, *return_property_value_data);

        int wasm_ptr = result.data->i32;

        void *value_ptr = m3ApiOffsetToPtr(wasm_ptr);
        memcpy(value_ptr, value, value_len);

        *return_property_value_data = wasm_ptr;
        *return_property_value_size = value_len;

        // printk("nasp: proxy_get_property ready, value_len: %d, return_property_value_data -> %d", value_len, *return_property_value_data);

        m3ApiReturn(WasmResult_Ok);
    }

    // printk("nasp: proxy_get_property WasmResult_NotFound");
    m3ApiReturn(WasmResult_NotFound);
}

m3ApiRawFunction(proxy_set_property)
{
    m3ApiReturnType(i32);

    m3ApiGetArgMem(char *, property_path_data);
    m3ApiGetArg(i32, property_path_size);

    m3ApiCheckMem(property_path_data, property_path_size);

    m3ApiGetArgMem(char *, property_value_data);
    m3ApiGetArg(i32, property_value_size);

    m3ApiCheckMem(property_value_data, property_value_size);

    proxywasm_filter *filter = _ctx->userdata;

    // printk("nasp: calling proxy_set_property '%.*s' (%d) -> %.*s (%d)", property_path_size, property_path_data, property_path_size, property_value_size, property_value_data, property_value_size);

    set_property(filter->proxywasm->current_context, property_path_data, property_path_size, property_value_data, property_value_size);

    m3ApiReturn(WasmResult_Ok);
}

m3ApiRawFunction(proxy_get_buffer_bytes)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, buffer_type);
    m3ApiGetArg(i32, start);
    m3ApiGetArg(i32, max_size);

    m3ApiGetArgMem(i32 *, return_buffer_data);
    m3ApiGetArgMem(i32 *, return_buffer_size);

    proxywasm_filter *filter = _ctx->userdata;

    char *value = NULL;
    int value_len = 0;
    // printk("nasp: calling proxy_get_buffer_bytes buffer_type '%d' (start: %d, max_size: %d)", buffer_type, start, max_size);

    get_buffer_bytes(filter->proxywasm->current_context, buffer_type, start, max_size, &value, &value_len);

    if (value_len > 0)
    {
        wasm_vm_result result = proxy_on_memory_allocate(filter, value_len);
        if (result.err)
        {
            FATAL("proxywasm proxy_on_memory_allocate error: %s", result.err);
            return m3Err_mallocFailed;
        }

        // printk("nasp: proxy_on_memory_allocate returned %d, value points to %p, size -> %d", result.data->i32, value, value_len);

        int wasm_ptr = result.data->i32;

        void *value_ptr = m3ApiOffsetToPtr(wasm_ptr);
        memcpy(value_ptr, value, value_len);

        *return_buffer_data = wasm_ptr;
        *return_buffer_size = value_len;

        // printk("nasp: get_buffer_bytes ready, value_len: %d, return_buffer_data -> %d", value_len, *return_buffer_data);

        m3ApiReturn(WasmResult_Ok);
    }

    printk("nasp: [%d] calling proxy_get_buffer_bytes buffer_type '%d'", filter->proxywasm->current_context->id, buffer_type);

    m3ApiReturn(WasmResult_NotFound);
}

m3ApiRawFunction(proxy_set_buffer_bytes)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, buffer_type);
    m3ApiGetArg(i32, start);
    m3ApiGetArg(i32, size);

    m3ApiGetArgMem(char *, buffer_data);
    m3ApiGetArg(i32, buffer_size);

    m3ApiCheckMem(buffer_data, buffer_size);

    proxywasm_filter *filter = _ctx->userdata;

    m3ApiReturn(set_buffer_bytes(filter->proxywasm->current_context, buffer_type, start, size, buffer_data, buffer_size));
}

static wasm_vm_result link_proxywasm_hostfunctions(proxywasm_filter *filter, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_log", "i(i*i)", proxy_log, filter)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_set_tick_period_milliseconds", "i(i)", proxy_set_tick_period_milliseconds, filter)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_get_property", "i(*i**)", proxy_get_property, filter)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_set_property", "i(*i*i)", proxy_set_property, filter)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_get_buffer_bytes", "i(iii**)", proxy_get_buffer_bytes, filter)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "proxy_set_buffer_bytes", "i(iii**)", proxy_set_buffer_bytes, filter)));

_catch:
    return (wasm_vm_result){.err = result};
}

void set_property_v(proxywasm_context *p, const char *key, const void *value, const int value_len)
{
    char path[256];
    int path_len = strlen(key);

    strcpy(path, key);

    int i;
    for (i = 0; i < path_len; i++)
    {
        if (path[i] == '.')
            path[i] = 0;
    }

    set_property(p, path, path_len, value, value_len);
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
    printk("nasp: %s key: %s", func, buf);
}

wasm_vm_result init_proxywasm_for(wasm_vm *vm, wasm_vm_module *module)
{
    proxywasm *proxywasm = proxywasms[wasm_vm_cpu(vm)];

    if (proxywasm == NULL)
    {
        proxywasm = kzalloc(sizeof(struct proxywasm), GFP_KERNEL);
        proxywasm->vm = vm;
        proxywasms[wasm_vm_cpu(vm)] = proxywasm;

        proxywasm_context *root_context = new_proxywasm_context(NULL, NULL, NULL);
        printk("nasp: root_context_id %d", root_context->id);

        proxywasm->root_context = root_context;
        proxywasm->current_context = root_context;

        {
            // TODO: this is only test data
            char empty_map[] = {0, 0, 0, 0};
            i64 listener_direction = ListenerDirectionInbound;
            set_property_v(root_context, "node.id", "lima", strlen("lima"));
            set_property_v(root_context, "node.metadata.NAME", "catalog-v1-6578575465-lz5h2", strlen("catalog-v1-6578575465-lz5h2"));
            set_property_v(root_context, "node.metadata.NAMESPACE", "kube-system", strlen("kube-system"));
            set_property_v(root_context, "node.metadata.OWNER", "blade-runner", strlen("blade-runner"));
            set_property_v(root_context, "node.metadata.WORKLOAD_NAME", "joska", strlen("joska"));
            set_property_v(root_context, "node.metadata.ISTIO_VERSION", "1.13.5", strlen("1.13.5"));
            set_property_v(root_context, "node.metadata.MESH_ID", "mesh1", strlen("mesh1"));
            set_property_v(root_context, "node.metadata.CLUSTER_ID", "cluster1", strlen("cluster1"));
            set_property_v(root_context, "node.metadata.LABELS", empty_map, sizeof(empty_map));
            set_property_v(root_context, "node.metadata.PLATFORM_METADATA", empty_map, sizeof(empty_map));
            set_property_v(root_context, "node.metadata.APP_CONTAINERS", "catalog", strlen("catalog"));
            set_property_v(root_context, "node.metadata.INSTANCE_IPS", "10.20.160.34,fe80::84cb:9eff:feb7:941b", strlen("10.20.160.34,fe80::84cb:9eff:feb7:941b"));
            set_property_v(root_context, "listener_direction", (char *)&listener_direction, sizeof(listener_direction));
            set_property_v(root_context, "plugin_root_id", "0", strlen("0"));
        }
    }

    proxywasm_filter *filter = kzalloc(sizeof(struct proxywasm_filter), GFP_KERNEL);
    filter->proxywasm = proxywasm;

    wasm_vm_result result;
    result = link_proxywasm_hostfunctions(filter, module);
    if (result.err)
    {
        kfree(proxywasm);
        return result;
    }

    strcpy(filter->name, module->name);

    wasm_vm_try_get_function(filter->proxy_on_memory_allocate, wasm_vm_get_function(vm, module->name, "malloc"));
    wasm_vm_try_get_function(filter->proxy_on_context_create, wasm_vm_get_function(vm, module->name, "proxy_on_context_create"));
    wasm_vm_try_get_function(filter->proxy_on_new_connection, wasm_vm_get_function(vm, module->name, "proxy_on_new_connection"));
    wasm_vm_try_get_function(filter->proxy_on_vm_start, wasm_vm_get_function(vm, module->name, "proxy_on_vm_start"));
    wasm_vm_try_get_function(filter->proxy_on_configure, wasm_vm_get_function(vm, module->name, "proxy_on_configure"));
    wasm_vm_try_get_function(filter->proxy_on_downstream_data, wasm_vm_get_function(vm, module->name, "proxy_on_downstream_data"));
    wasm_vm_try_get_function(filter->proxy_on_downstream_connection_close, wasm_vm_get_function(vm, module->name, "proxy_on_downstream_connection_close"));
    wasm_vm_try_get_function(filter->proxy_on_upstream_data, wasm_vm_get_function(vm, module->name, "proxy_on_upstream_data"));
    wasm_vm_try_get_function(filter->proxy_on_upstream_connection_close, wasm_vm_get_function(vm, module->name, "proxy_on_upstream_connection_close"));
    wasm_vm_try_get_function(filter->proxy_on_tick, wasm_vm_get_function(vm, module->name, "proxy_on_tick"));
    wasm_vm_try_get_function(filter->proxy_on_done, wasm_vm_get_function(vm, module->name, "proxy_on_done"));
    wasm_vm_try_get_function(filter->proxy_on_delete, wasm_vm_get_function(vm, module->name, "proxy_on_delete"));

error:
    if (result.err)
    {
        FATAL("proxywasm function lookups failed for module %s failed: %s -> %s", module->name, result.err, wasm_vm_last_error(module));
        kfree(proxywasm);
        return result;
    }

    // Create the root context
    result = wasm_vm_call_direct(vm, filter->proxy_on_context_create, proxywasm->root_context->id, 0);
    if (result.err)
    {
        FATAL("proxy_on_context_create for module %s failed: %s -> %s", module->name, result.err, wasm_vm_last_error(module));
        kfree(proxywasm);
        return result;
    }

    result = wasm_vm_call_direct(vm, filter->proxy_on_vm_start, proxywasm->root_context->id, 0);
    if (result.err)
    {
        FATAL("proxy_on_vm_start for module %s failed: %s", module->name, result.err)
        kfree(proxywasm);
        return result;
    }

    i32 plugin_configuration_size = 0; // TODO

    result = wasm_vm_call_direct(vm, filter->proxy_on_configure, proxywasm->root_context->id, plugin_configuration_size);
    if (result.err)
    {
        FATAL("proxy_on_configure for module %s failed: %s", module->name, result.err)
        kfree(proxywasm);
        return result;
    }

    if (proxywasm->filters == NULL)
    {
        proxywasm->filters = filter;
    }
    else
    {
        proxywasm_filter *cur = proxywasm->filters;
        while (cur->next != NULL)
        {
            cur = cur->next;
        }
        cur->next = filter;
    }

    return wasm_vm_result_ok;
}

wasm_vm_result proxywasm_create_context(proxywasm *p, buffer_t *upstream_buffer, buffer_t *downstream_buffer)
{
    proxywasm_context *context = new_proxywasm_context(p->root_context, upstream_buffer, downstream_buffer);
    p->current_context = context;
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_context_create, p->current_context->id, p->root_context->id));
}

wasm_vm_result proxywasm_destroy_context(proxywasm *p)
{
    wasm_vm_result result;
    proxywasm_filter *f;
    for (f = p->filters; f != NULL; f = f->next)
    {
        result = wasm_vm_call_direct(p->vm, f->proxy_on_done, p->current_context->id);
        if (result.err != NULL)
        {
            pr_err("nasp: calling %s.proxy_on_done errored %s", f->name, result.err);
        }

        result = wasm_vm_call_direct(p->vm, f->proxy_on_delete, p->current_context->id);
        if (result.err != NULL)
        {
            pr_err("nasp: calling %s.proxy_on_delete errored %s", f->name, result.err);
        }
    }

    free_proxywasm_context(p->current_context);

    return wasm_vm_result_ok;
}

wasm_vm_result proxy_on_context_create(proxywasm *p, i32 context_id, i32 root_context_id)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_context_create, context_id, root_context_id));
}

wasm_vm_result proxy_on_new_connection(proxywasm *p)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_new_connection, p->current_context->id));
}

wasm_vm_result proxy_on_downstream_data(proxywasm *p, i32 data_size, bool end_of_stream)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_downstream_data, p->current_context->id, data_size, end_of_stream));
}

wasm_vm_result proxy_on_downstream_connection_close(proxywasm *p, PeerType peer_type)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_downstream_connection_close, p->current_context->id, peer_type));
}

wasm_vm_result proxy_on_upstream_data(proxywasm *p, i32 data_size, bool end_of_stream)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_upstream_data, p->current_context->id, data_size, end_of_stream));
}

wasm_vm_result proxy_on_upstream_connection_close(proxywasm *p, PeerType peer_type)
{
    FOR_ALL_FILTERS(wasm_vm_call_direct(p->vm, f->proxy_on_upstream_connection_close, p->current_context->id, peer_type));
}

void set_property(proxywasm_context *p, const char *key, int key_len, const char *value, int value_len)
{
    struct property_h_node *cur, *node = kmalloc(sizeof(struct property_h_node), GFP_KERNEL);
    uint32_t key_i = xxh32(key, key_len, 0);
    print_property_key("set_property", key, key_len);
    printk("nasp: set_property key hash %u, key len: %d, value: '%.*s'", key_i, key_len, value_len, value);

    node->key_len = key_len;
    memcpy(node->key, key, key_len);
    node->value_len = value_len;
    node->value = (char *)kmalloc(value_len, GFP_KERNEL);
    memcpy(node->value, value, value_len);

    hash_add(p->properties, &node->node, key_i, HASHTABLE_BITS);
}

void get_property(proxywasm_context *p, const char *key, int key_len, char **value, int *value_len)
{
    property_h_node *cur = NULL;
    property_h_node *temp = NULL;
    uint32_t key_i = xxh32(key, key_len, 0);
    // print_property_key("get_property", key, key_len);
    // printk("nasp: context [%d] key hash %u, key len: %d key: '%.*s'", p->id, key_i, key_len, key_len, key);

    hash_for_each_possible(p->properties, cur, node, key_i, HASHTABLE_BITS)
    {
        if (cur->key_len == key_len && memcmp(cur->key, key, key_len) == 0)
        {
            temp = cur;
            break;
        }
    }

    if (!temp)
    {
        if (p->parent != NULL)
        {
            // printk("nasp: '%.*s' key not found, searching in parent", key_len, key);
            get_property(p->parent, key, key_len, value, value_len);
        }
        else
        {
            printk("nasp: '%.*s' key not found", key_len, key);
        }

        return;
    }

    // printk("nasp: '%.*s' key found, value: %.*s", key_len, key, temp->value_len, temp->value);

    *value = temp->value;
    *value_len = temp->value_len;
}

void get_buffer_bytes(proxywasm_context *p, BufferType buffer_type, i32 start, i32 max_size, char **value, i32 *value_len)
{
    // printk("nasp: [%d] get_buffer_bytes BufferType: %d, start: %d, max_size: %d", p->id, buffer_type, start, max_size);

    switch (buffer_type)
    {
    case DownstreamData:
        *value = p->downstream_buffer->data + start;
        *value_len = min(max_size, p->downstream_buffer->size - start);
        break;
    case UpstreamData:
        *value = p->upstream_buffer->data + start;
        *value_len = min(max_size, p->upstream_buffer->size - start);
        break;
    default:
        pr_err("nasp: get_buffer_bytes: unknown buffer type %d", buffer_type);
        break;
    }
}

WasmResult set_buffer_bytes(proxywasm_context *p, BufferType buffer_type, i32 start, i32 size, char *value, i32 value_len)
{
    WasmResult result = WasmResult_Ok;

    switch (buffer_type)
    {
    case DownstreamData:
        // printk("nasp: [%d] set_buffer_bytes BufferType: %d, start: %d, size: %d, value_len: %d, buffer_size: %d", p->id, buffer_type, start, size, value_len, p->downstream_buffer->size);

        if (start == 0)
        {
            if (size == 0)
            {
                // realloc if needed
                // if (p->buffer_size + value_len > p->buffer_size)
                // {
                //     p->buffer = krealloc(p->buffer->data, p->buffer_size + value_len, GFP_KERNEL);
                // }

                // prepend
                memmove(p->downstream_buffer->data + value_len, p->downstream_buffer->data, p->downstream_buffer->size);
                memcpy(p->downstream_buffer->data, value, value_len);
                p->downstream_buffer->size += value_len;
            }
            else
            {
                // // realloc if needed
                // if (value_len > p->buffer_size)
                // {
                //     p->buffer = krealloc(p->buffer->data, value_len, GFP_KERNEL);
                // }

                memcpy(p->downstream_buffer->data, value, value_len);
                p->downstream_buffer->size = value_len;
            }
        }
        else if (start >= p->downstream_buffer->size)
        {
            // TODO handle realloc here
            memcpy(p->downstream_buffer->data + p->downstream_buffer->size, value, value_len);
            p->downstream_buffer->size += value_len;
        }
        else
        {
            result = WasmResult_BadArgument;
        }

        // printk("nasp: [%d] set_buffer_bytes: done downstream buffer size: %d", p->id, p->downstream_buffer->size);

        break;
    case UpstreamData:
        // printk("nasp: [%d] set_buffer_bytes BufferType: %d, start: %d, size: %d, value_len: %d, buffer_size: %d", p->id, buffer_type, start, size, value_len, p->upstream_buffer_size);

        if (start == 0)
        {
            if (size == 0)
            {
                // realloc if needed
                // if (p->buffer_size + value_len > p->buffer_size)
                // {
                //     p->buffer = krealloc(p->buffer->data, p->buffer->size + value_len, GFP_KERNEL);
                // }

                // prepend
                memmove(p->upstream_buffer->data + value_len, p->upstream_buffer->data, p->upstream_buffer->size);
                memcpy(p->upstream_buffer->data, value, value_len);
                p->upstream_buffer->size += value_len;
            }
            else
            {
                // // realloc if needed
                // if (value_len > p->buffer_size)
                // {
                //     p->buffer = krealloc(p->buffer, value_len, GFP_KERNEL);
                // }

                memcpy(p->upstream_buffer->data, value, value_len);
                p->upstream_buffer->size = value_len;
            }
        }
        else if (start >= p->upstream_buffer->size)
        {
            // TODO handle realloc here
            memcpy(p->upstream_buffer->data + p->upstream_buffer->size, value, value_len);
            p->upstream_buffer->size += value_len;
        }
        else
        {
            result = WasmResult_BadArgument;
        }

        // printk("nasp: [%d] set_buffer_bytes: done upstream buffer size: %d", p->id, p->upstream_buffer_size);

        break;
    default:
        pr_err("nasp: set_buffer_bytes: unknown buffer type %d", buffer_type);
        result = WasmResult_NotFound;
        break;
    }

    return result;
}
