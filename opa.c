/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "opa.h"
#include "json.h"
#include "runtime.h"

#define JSON_MAX_LEN 32

typedef struct opa_wrapper
{
    wasm_vm *vm;
    IM3Function malloc;
    IM3Function free;
    void **builtins;
    IM3Function eval;
    IM3Function json_dump;
} opa_wrapper;

static opa_wrapper *opas[NR_CPUS] = {};

wasm_vm_result opa_malloc(opa_wrapper *opa, unsigned size)
{
    return wasm_vm_call_direct(opa->vm, opa->malloc, size);
}

wasm_vm_result opa_free(opa_wrapper *opa, i32 ptr)
{
    return wasm_vm_call_direct(opa->vm, opa->free, ptr);
}

opa_wrapper *this_cpu_opa(void)
{
    int cpu = get_cpu();
    put_cpu();
    return opas[cpu];
}

i32 time_now_ns(opa_wrapper *opa)
{
    u64 now = ktime_get_real_ns();

    wasm_vm_result result = opa_malloc(opa, sizeof(now));
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        return 0;
    }

    uint8_t *mem = wasm_vm_memory(opa->vm);
    i32 addr = result.data->i32;

    memcpy(mem + addr, &now, sizeof(now));

    return addr;
}

int parse_opa_builtins(opa_wrapper *opa, char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        JSON_Object *object = json_object(root_value);
        int builtins = json_object_get_count(object);
        printk("wasm: opa module builtins = %s", json);

        // indexing starts from 1 for some reason, so we need one bigger array
        opa->builtins = kmalloc(builtins + 1 * sizeof(void*), GFP_KERNEL);

        int i;
        for (i = 0; i < builtins; i++)
        {
            const char *name = json_object_get_name(object, i);
            const int64_t builtin_id = json_object_get_number(object, name);
            if (strcmp(name, "time.now_ns") == 0)
            {
                opa->builtins[builtin_id] = time_now_ns;
            }
            else
            {
                printk(KERN_WARNING "wasm: this opa module uses an unsupported builtin function: %s", name);
            }
        }

        json_value_free(root_value);
        return builtins;
    }
    return 0;
}

int parse_opa_eval_result(char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        JSON_Array *results = json_value_get_array(root_value);
        JSON_Object *result = json_array_get_object(results, 0);
        int ret = json_object_get_boolean(result, "result");
        json_value_free(root_value);
        return ret;
    }
    return false;
}

m3ApiRawFunction(opa_abort)
{
    m3ApiGetArgMem(char*, addr);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    printk("wasm: calling opa_abort %s", addr);

    m3ApiSuccess();
}

m3ApiRawFunction(opa_builtin0)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    printk("wasm: calling opa_builtin0 %d", builtin_id);

    i32 (*builtin)(opa_wrapper *) = opa->builtins[builtin_id];

    m3ApiReturn(builtin(opa));
}

static wasm_vm_result link_opa_builtins(opa_wrapper *opa, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_abort", "(i)", &opa_abort, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin0", "i(ii)", &opa_builtin0, opa)));

_catch:
    return (wasm_vm_result){.err = result};
}

wasm_vm_result init_opa_for(wasm_vm *vm)
{
    opa_wrapper *opa = kmalloc(sizeof(opa_wrapper), GFP_KERNEL);
    opa->malloc = wasm_vm_get_function(vm, OPA_MODULE, "opa_malloc");
    opa->free = wasm_vm_get_function(vm, OPA_MODULE, "opa_free");
    opa->eval = wasm_vm_get_function(vm, OPA_MODULE, "opa_eval");
    opa->json_dump = wasm_vm_get_function(vm, OPA_MODULE, "opa_json_dump");
    opa->vm = vm;

    wasm_vm_function *builtinsFunc = wasm_vm_get_function(vm, OPA_MODULE, "builtins");
    wasm_vm_result result = wasm_vm_call_direct(vm, builtinsFunc);
    if (result.err)
    {
        kfree(opa);
        return result;
    }

    result = wasm_vm_call_direct(vm, opa->json_dump, result.data->i32);
    if (result.err)
    {
        kfree(opa);
        return result;
    }

    uint8_t *memory = wasm_vm_memory(vm);

    // parse and link
    char *builtins = memory + result.data->i32;
    if (parse_opa_builtins(opa, builtins) > 0)
    {
        result = link_opa_builtins(opa, wasm_vm_get_module(vm, OPA_MODULE));
        if (result.err)
        {
            kfree(opa->builtins);
            kfree(opa);
            return result;
        }
    }

    // opa_free(opa, result.data->i32);

    opas[vm->cpu] = opa;

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result opa_eval(opa_wrapper *opa, i32 inputAddr, i32 inputLen)
{
    i32 entrypoint = 0;
    i32 dataAddr = 0;
    i32 heapAddr = 0;
    i32 format = 0;

    return wasm_vm_call_direct(opa->vm, opa->eval, 0, entrypoint, dataAddr, inputAddr, inputLen, heapAddr, format);
}

int this_cpu_opa_eval(int protocol)
{
    int ret = false;
    i32 jsonAddr = 0;
    i32 jsonLen = 0;
    wasm_vm_result result;

    wasm_vm *vm = this_cpu_wasm_vm();
    wasm_vm_lock(vm);

    opa_wrapper *opa = this_cpu_opa();
    if (!opa)
    {
        ret = 1;
        pr_warn("wasm: opa policy module not loaded, eval always evalautes to true");
        goto cleanup;
    }

    result = opa_malloc(opa, JSON_MAX_LEN);
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        goto cleanup;
    }

    uint8_t *mem = wasm_vm_memory(vm);

    jsonAddr = result.data->i32;
    jsonLen = sprintf(mem + jsonAddr, "{\"protocol\":%d}", protocol);

    result = opa_eval(opa, jsonAddr, jsonLen);
    if (result.err)
    {
        FATAL("opa_eval error: %s", result.err);
        goto cleanup;
    }

    char *res = (char *)(mem + result.data->i32);

    printk("wasm: opa result: %s", res);

    ret = parse_opa_eval_result(res);

    printk("wasm: opa result parsed: %d", ret);

cleanup:
    if (jsonAddr != 0)
    {
        result = opa_free(opa, jsonAddr);
        if (result.err)
            FATAL("opa wasm_vm_opa_free json error: %s", result.err);
    }

    wasm_vm_unlock(vm);
    return ret;
}
