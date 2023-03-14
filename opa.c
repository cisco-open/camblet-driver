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

typedef struct opa_wrapper
{
    wasm_vm *vm;
    IM3Function malloc;
    IM3Function free;
    IM3Function builtins;
    IM3Function eval;
    IM3Function json_dump;
} opa_wrapper;

static opa_wrapper *opas[NR_CPUS];

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
    return opas[smp_processor_id()];
}

int parse_opa_builtins(char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        JSON_Object *builtins = json_object(root_value);
        int ret = json_object_get_count(builtins);
        json_value_free(root_value);
        return ret;
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

wasm_vm_result init_opa_for(wasm_vm *vm)
{
    opa_wrapper *opa = kmalloc(sizeof(opa_wrapper), GFP_KERNEL);
    opa->builtins = wasm_vm_get_function(vm, OPA_MODULE, "builtins");
    opa->malloc = wasm_vm_get_function(vm, OPA_MODULE, "opa_malloc");
    opa->free = wasm_vm_get_function(vm, OPA_MODULE, "opa_free");
    opa->eval = wasm_vm_get_function(vm, OPA_MODULE, "opa_eval");
    opa->json_dump = wasm_vm_get_function(vm, OPA_MODULE, "opa_json_dump");
    opa->vm = vm;

    wasm_vm_result result = wasm_vm_call_direct(vm, opa->builtins);
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

    // warn for builtins
    char *builtins = memory + result.data->i32;
    if (parse_opa_builtins(builtins) > 0)
    {
        printk("WARNING: this opa module has builtins, but they are not supported yet: %s", builtins);
    }

    opa_free(opa, result.data->i32);

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

#define JSON_MAX_LEN 32

int this_cpu_opa_eval(int protocol)
{
    int ret = false;
    i32 jsonAddr = 0;
    i32 jsonLen = 0;
    wasm_vm_result result;

    wasm_vm *vm = this_cpu_wasm_vm();
    wasm_vm_lock(vm);

    opa_wrapper *opa = this_cpu_opa();

    if (!opa->vm)
    {
        goto cleanup;
    }

    uint8_t *mem = wasm_vm_memory(vm);
    if (!mem)
    {
        goto cleanup;
    }

    result = opa_malloc(opa, JSON_MAX_LEN);
    if (result.err)
    {
        FATAL("opa wasm_vm_opa_malloc error: %s", result.err);
        goto cleanup;
    }

    jsonAddr = result.data->i32;
    jsonLen = sprintf(mem + jsonAddr, "{\"protocol\":%d}", protocol);

    result = opa_eval(opa, jsonAddr, jsonLen);
    if (result.err)
    {
        FATAL("opa_eval error: %s", result.err);
        goto cleanup;
    }

    char *res = (char *)(mem + result.data->i32);

    printk("opa result: %s", res);

    ret = parse_opa_eval_result(res);

    printk("opa result parsed: %d", ret);

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
