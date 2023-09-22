/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include "opa.h"
#include "json.h"

typedef struct opa_wrapper
{
    wasm_vm *vm;
    wasm_vm_function *malloc;
    wasm_vm_function *free;
    wasm_vm_function *eval;
    wasm_vm_function *json_dump;
    wasm_vm_function *value_dump;
    void **builtins;
} opa_wrapper;

static opa_wrapper *opas[NR_CPUS] = {0};

static wasm_vm_result opa_malloc(opa_wrapper *opa, unsigned size)
{
    return wasm_vm_call_direct(opa->vm, opa->malloc, size);
}

static wasm_vm_result opa_free(opa_wrapper *opa, i32 ptr)
{
    return wasm_vm_call_direct(opa->vm, opa->free, ptr);
}

opa_wrapper *this_cpu_opa(void)
{
    int cpu = get_cpu();
    put_cpu();
    return opas[cpu];
}

static i32 time_now_ns(opa_wrapper *opa, i32 _ctx)
{
    u64 now = ktime_get_real_ns();

    wasm_vm_result result = opa_malloc(opa, sizeof(now));
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        return 0;
    }

    uint8_t *mem = wasm_vm_memory(opa->eval->module);
    i32 addr = result.data->i32;

    memcpy(mem + addr, &now, sizeof(now));

    return addr;
}

static i32 trace(opa_wrapper *opa, i32 _ctx, i32 arg1)
{
    uint8_t *mem = wasm_vm_memory(opa->eval->module);

    wasm_vm_result result = wasm_vm_call_direct(opa->vm, opa->value_dump, arg1);
    if (result.err)
    {
        FATAL("opa wasm_vm_value_dump error: %s", result.err);
        return 0;
    }

    printk("nasp: opa: Note %s", (char *)(mem + result.data->i32));

    result = opa_malloc(opa, sizeof(true));
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        return 0;
    }

    i32 addr = result.data->i32;

    int true = true;

    memcpy(mem + addr, &true, sizeof(true));

    return addr;
}

static int parse_opa_builtins(opa_wrapper *opa, char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        JSON_Object *object = json_object(root_value);
        int builtins = json_object_get_count(object);
        printk("nasp: opa module builtins = %s", json);

        // indexing starts from 1 for some reason, so we need one bigger array
        opa->builtins = kzalloc(builtins + 1 * sizeof(void *), GFP_KERNEL);

        int i;
        for (i = 0; i < builtins; i++)
        {
            const char *name = json_object_get_name(object, i);
            const int64_t builtin_id = json_object_get_number(object, name);
            if (strcmp(name, "time.now_ns") == 0)
            {
                opa->builtins[builtin_id] = time_now_ns;
            }
            else if (strcmp(name, "trace") == 0)
            {
                opa->builtins[builtin_id] = trace;
            }
            else
            {
                printk(KERN_WARNING "nasp: this opa module uses an unsupported builtin function: %s", name);
            }
        }

        json_value_free(root_value);
        return builtins;
    }
    return 0;
}

static int parse_opa_eval_result(char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        JSON_Array *results = json_value_get_array(root_value);
        JSON_Object *result = json_array_get_object(results, 0);
        int ret = json_object_get_boolean(result, "result");
        json_value_free(root_value);
        if (ret == -1)
        {
            ret = false;
        }
        return ret;
    }
    return false;
}

opa_socket_context parse_opa_socket_eval_result(char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    opa_socket_context ret = {0};
    if (root_value)
    {
        JSON_Array *results = json_value_get_array(root_value);
        JSON_Object *result = json_array_get_object(results, 0);
        if (result == NULL)
            goto free;

        int permissive = json_object_dotget_boolean(result, "result.permissive");
        if (permissive == -1)
            permissive = false;

        int mtls = json_object_dotget_boolean(result, "result.mtls");
        if (mtls == -1)
            mtls = false;

        ret.permissive = permissive;
        ret.mtls = mtls;
        ret.allowed = true;

    free:
        json_value_free(root_value);
    }
    return ret;
}

m3ApiRawFunction(opa_abort)
{
    m3ApiGetArgMem(char *, addr);
    pr_err("nasp: opa_abort: %s", addr);
    m3ApiTrap(m3Err_trapAbort);
}

m3ApiRawFunction(opa_println)
{
    m3ApiGetArgMem(char *, addr);
    printk(addr);
    m3ApiSuccess();
}

m3ApiRawFunction(opa_builtin0)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    printk("nasp: calling opa_builtin0 %d", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("nasp: opa_builtin0 %d not found", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx));
}

m3ApiRawFunction(opa_builtin1)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);
    m3ApiGetArg(i32, _1);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    printk("nasp: calling opa_builtin1 %d", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("nasp: opa_builtin1 %d not found", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx, _1));
}

static wasm_vm_result link_opa_builtins(opa_wrapper *opa, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_abort", "(i)", opa_abort, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_println", "(i)", opa_println, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin0", "i(ii)", opa_builtin0, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin1", "i(iii)", opa_builtin1, opa)));

_catch:
    return (wasm_vm_result){.err = result};
}

wasm_vm_result init_opa_for(wasm_vm *vm, wasm_vm_module *module)
{
    wasm_vm_result result;
    wasm_vm_function *builtinsFunc;

    opa_wrapper *opa = kmalloc(sizeof(struct opa_wrapper), GFP_KERNEL);
    wasm_vm_try_get_function(opa->malloc, wasm_vm_get_function(vm, module->name, "opa_malloc"));
    wasm_vm_try_get_function(opa->free, wasm_vm_get_function(vm, module->name, "opa_free"));
    wasm_vm_try_get_function(opa->eval, wasm_vm_get_function(vm, module->name, "opa_eval"));
    wasm_vm_try_get_function(opa->json_dump, wasm_vm_get_function(vm, module->name, "opa_json_dump"));
    wasm_vm_try_get_function(opa->value_dump, wasm_vm_get_function(vm, module->name, "opa_value_dump"));
    wasm_vm_try_get_function(builtinsFunc, wasm_vm_get_function(vm, module->name, "builtins"));
    opa->vm = vm;

    result = wasm_vm_call_direct(vm, builtinsFunc);
    if (result.err)
        goto error;

    result = wasm_vm_call_direct(vm, opa->json_dump, result.data->i32);

error:
    if (result.err)
    {
        kfree(opa);
        return result;
    }

    uint8_t *memory = wasm_vm_memory(opa->eval->module);
    i32 builtinsJson = result.data->i32;

    // parse and link
    char *builtins = memory + builtinsJson;
    if (parse_opa_builtins(opa, builtins) > 0)
    {
        result = link_opa_builtins(opa, module);
        if (result.err)
        {
            kfree(opa->builtins);
            kfree(opa);
            return result;
        }
    }

    opa_free(opa, builtinsJson);

    opas[wasm_vm_cpu(vm)] = opa;

    return wasm_vm_result_ok;
}

static wasm_vm_result opa_eval(opa_wrapper *opa, i32 inputAddr, i32 inputLen)
{
    i32 entrypoint = 0;
    i32 dataAddr = 0;
    i32 heapAddr = 0;
    i32 format = 0; // 0 is JSON, 1 is “value”, i.e. serialized Rego values

    return wasm_vm_call_direct(opa->vm, opa->eval, 0, entrypoint, dataAddr, inputAddr, inputLen, heapAddr, format);
}

int this_cpu_opa_eval(const char *input)
{
    int ret = false;
    i32 inputAddr = 0;
    i32 inputLen = strlen(input) + 1;
    wasm_vm_result result;

    opa_wrapper *opa = this_cpu_opa();
    printk("nasp: opa %s.eval input: %s", opa->eval->module->name, input);

    wasm_vm_lock(opa->vm);

    if (!opa)
    {
        ret = true;
        pr_warn("nasp: opa policy module not loaded, eval always evalautes to true");
        goto cleanup;
    }

    result = opa_malloc(opa, inputLen);
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        goto cleanup;
    }

    uint8_t *memory = wasm_vm_memory(opa->eval->module);

    inputAddr = result.data->i32;
    memcpy(memory + inputAddr, input, inputLen);

    result = opa_eval(opa, inputAddr, inputLen);
    if (result.err)
    {
        FATAL("wasm_vm_opa_eval error: %s", result.err);
        goto cleanup;
    }

    char *json = (char *)(memory + result.data->i32);
    ret = parse_opa_eval_result(json);

    printk("nasp: opa %s.eval result: %s -> %d", opa->eval->module->name, json, ret);

cleanup:
    if (inputAddr != 0)
    {
        result = opa_free(opa, inputAddr);
        if (result.err)
            FATAL("opa wasm_vm_opa_free json error: %s", result.err);
    }

    wasm_vm_unlock(opa->vm);
    return ret;
}

opa_socket_context this_cpu_opa_socket_eval(const char *input)
{
    opa_socket_context ret = {0};
    i32 inputAddr = 0;
    i32 inputLen = strlen(input) + 1;
    wasm_vm_result result;

    opa_wrapper *opa = this_cpu_opa();
    printk("nasp: opa %s.eval input: %s", opa->eval->module->name, input);

    wasm_vm_lock(opa->vm);

    if (!opa)
    {
        pr_warn("nasp: opa socket policy module not loaded, eval always evaluates to NULL");
        goto cleanup;
    }

    result = opa_malloc(opa, inputLen);
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        goto cleanup;
    }

    uint8_t *memory = wasm_vm_memory(opa->eval->module);

    inputAddr = result.data->i32;
    memcpy(memory + inputAddr, input, inputLen);

    result = opa_eval(opa, inputAddr, inputLen);
    if (result.err)
    {
        FATAL("wasm_vm_opa_eval error: %s", result.err);
        goto cleanup;
    }

    char *json = (char *)(memory + result.data->i32);
    ret = parse_opa_socket_eval_result(json);

    printk("nasp: opa %s.eval result: %s -> %d", opa->eval->module->name, json, ret.allowed);

cleanup:
    if (inputAddr != 0)
    {
        result = opa_free(opa, inputAddr);
        if (result.err)
            FATAL("opa wasm_vm_opa_free json error: %s", result.err);
    }

    wasm_vm_unlock(opa->vm);
    return ret;
}
