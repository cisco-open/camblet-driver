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
#include "string.h"

typedef struct opa_wrapper
{
    wasm_vm *vm;
    wasm_vm_function *malloc;
    wasm_vm_function *free;
    wasm_vm_function *eval;
    wasm_vm_function *json_dump;
    wasm_vm_function *value_dump;
    wasm_vm_function *value_parse;
    wasm_vm_function *value_free;
    void **builtins;

    i32 dataValueAddr;
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

static wasm_vm_result opa_value_free(opa_wrapper *opa, i32 ptr)
{
    return wasm_vm_call_direct(opa->vm, opa->value_free, ptr);
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

void opa_socket_context_free(opa_socket_context ctx)
{
    kfree(ctx.id);
    kfree(ctx.dns);
    kfree(ctx.uri);

    if (ctx.allowed_spiffe_ids_length == 0)
    {
        return;
    }

    int i;
    for (i = 0; i < ctx.allowed_spiffe_ids_length; i++)
    {
        kfree(ctx.allowed_spiffe_ids[i]);
    }
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
    opa_socket_context ret = {};

    if (root_value)
    {
        JSON_Array *results = json_value_get_array(root_value);
        JSON_Object *result = json_array_get_object(results, 0);
        if (result == NULL)
            goto free;

        JSON_Array *policies;

        policies = json_object_dotget_array(result, "result.policies_with_egress");
        if (json_array_get_count(policies) == 0)
        {
            policies = json_object_dotget_array(result, "result.policies");
        }

        if (json_array_get_count(policies) == 0)
        {
            goto free;
        }

        int i;
        int policy_prio = -1;
        int egress_prio = -1;
        JSON_Object *matched_policy;

        // find highest policy prio
        for (i = 0; i < json_array_get_count(policies); i++)
        {
            JSON_Object *policy = json_array_get_object(policies, i);
            if (policy == NULL)
            {
                goto free;
            }
            int nr = json_object_get_number(policy, "nr");
            if (nr < policy_prio || policy_prio == -1)
            {
                policy_prio = nr;
            }
        }

        // find highest egress prio
        for (i = 0; i < json_array_get_count(policies); i++)
        {
            JSON_Object *policy = json_array_get_object(policies, i);
            if (policy == NULL)
            {
                goto free;
            }
            int nr = json_object_get_number(policy, "nr");
            if (nr != policy_prio)
            {
                continue;
            }
            int enr = json_object_dotget_number(policy, "egress.nr");
            if (enr < egress_prio || egress_prio == -1)
            {
                egress_prio = enr;
                matched_policy = policy;
            }
        }

        pr_info("nasp: opa result policy_prio [%d], egress_prio [%d]\n", policy_prio, egress_prio);
        pr_info("nasp: matched policy %s", json_serialize_to_string(json_object_get_wrapping_value(matched_policy)));

        size_t egress_id_len = json_object_dotget_string_len(matched_policy, "egress.id");
        size_t id_len = json_object_dotget_string_len(matched_policy, "id");
        if (egress_id_len > 0 || id_len > 0)
        {
            ret.id = kzalloc(egress_id_len + id_len + 1, GFP_KERNEL);
            if (id_len > 0)
            {
                strcat(ret.id, json_object_dotget_string(matched_policy, "id"));
            }
            if (egress_id_len > 0)
            {
                strcat(ret.id, json_object_dotget_string(matched_policy, "egress.id"));
            }
        }

        // defaults
        ret.mtls = true;
        ret.allowed = true;

        JSON_Array *allowed_spiffe_ids = json_object_dotget_array(matched_policy, "egress.policy.spiffeID");
        if (allowed_spiffe_ids == NULL)
            allowed_spiffe_ids = json_object_dotget_array(matched_policy, "policy.spiffeID");
        if (allowed_spiffe_ids != NULL)
        {
            char *allowed_spiffe_id;
            ret.allowed_spiffe_ids_length = json_array_get_count(allowed_spiffe_ids);
            for (i = 0; i < ret.allowed_spiffe_ids_length; i++)
            {
                ret.allowed_spiffe_ids[i] = strdup(json_array_get_string(allowed_spiffe_ids, i));
            }
        }

        int mtls = json_object_dotget_boolean(matched_policy, "egress.properties.mtls");
        if (mtls == -1)
            mtls = json_object_dotget_boolean(matched_policy, "properties.mtls");
        if (mtls == 0)
            ret.mtls = false;
        else if (mtls == 1)
            ret.mtls = true;

        char *workload_id = json_object_dotget_string(matched_policy, "egress.properties.workloadID");
        if (workload_id == NULL)
            workload_id = json_object_dotget_string(matched_policy, "properties.workloadID");
        if (workload_id != NULL)
        {
            int workload_id_len = strlen(workload_id) + 24;
            ret.uri = kzalloc(workload_id_len + 1, GFP_KERNEL);
            snprintf(ret.uri, workload_id_len, "spiffe://cluster.local/%s", workload_id);
        }

        JSON_Array *dns = json_object_dotget_array(matched_policy, "egress.properties.dns");
        if (dns == NULL)
            dns = json_object_dotget_array(matched_policy, "properties.dns");
        if (dns != NULL)
        {
            int dns_len = 0;
            for (i = 0; i < json_array_get_count(dns); i++)
            {
                dns_len += json_array_get_string_len(dns, i);
                if (i < json_array_get_count(dns) - 1)
                {
                    dns_len += 1;
                }
            }

            ret.dns = kzalloc(dns_len + 1, GFP_KERNEL);
            for (i = 0; i < json_array_get_count(dns); i++)
            {
                strcat(ret.dns, json_array_get_string(dns, i));
                if (i < json_array_get_count(dns) - 1)
                {
                    strcat(ret.dns, ",");
                }
            }
        }

        if (!ret.uri)
        {
            ret.uri = strndup("spiffe://unspecified", 20);
        }

        if (!ret.dns)
        {
            ret.dns = strndup("example.org", 11);
        }

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
    wasm_vm_try_get_function(opa->value_parse, wasm_vm_get_function(vm, module->name, "opa_json_parse"));
    wasm_vm_try_get_function(opa->value_free, wasm_vm_get_function(vm, module->name, "opa_value_free"));
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

static wasm_vm_result opa_value_parse(opa_wrapper *opa, i32 dataAddr, i32 dataLen)
{
    return wasm_vm_call_direct(opa->vm, opa->value_parse, dataAddr, dataLen);
}

static wasm_vm_result opa_eval(opa_wrapper *opa, i32 inputAddr, i32 inputLen)
{
    i32 entrypoint = 0;
    i32 heapAddr = 0;
    i32 format = 0; // 0 is JSON, 1 is “value”, i.e. serialized Rego values

    return wasm_vm_call_direct(opa->vm, opa->eval, 0, entrypoint, opa->dataValueAddr, inputAddr, inputLen, heapAddr, format);
}

int this_cpu_opa_eval(const char *input)
{
    int ret = false;
    i32 inputAddr = 0;
    i32 inputLen = strlen(input);
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
    i32 inputLen = strlen(input);
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

    printk("nasp: opa %s.eval result: id[%s] allowed[%d] mtls[%d]", opa->eval->module->name, ret.id, ret.allowed, ret.mtls);

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

void load_opa_data(unsigned char *data)
{
    i32 dataAddr = 0;
    i32 dataLen = strlen(data) + 1;

    unsigned cpu;
    for_each_possible_cpu(cpu)
    {
        pr_info("nasp: load_opa_data cpu[%d]", cpu);
        opa_wrapper *opa = opas[cpu];

        wasm_vm_lock(opa->vm);

        wasm_vm_result result;

        if (opa->dataValueAddr > 0)
        {
            result = opa_value_free(opa, opa->dataValueAddr);
            if (result.err)
                FATAL("load_opa_data opa_value_free error: %s", result.err);
            opa->dataValueAddr = 0;
            printk("free nasp data");
        }

        result = opa_malloc(opa, dataLen);
        if (result.err)
        {
            FATAL("load_opa_data opa_malloc error: %s", result.err);
            wasm_vm_unlock(opa->vm);

            continue;
        }

        uint8_t *memory = wasm_vm_memory(opa->value_parse->module);

        dataAddr = result.data->i32;
        memcpy(memory + dataAddr, data, dataLen);

        result = opa_value_parse(opa, dataAddr, dataLen);
        if (result.err)
        {
            FATAL("load_opa_data opa_value_parse error: %s", result.err);
            wasm_vm_unlock(opa->vm);

            continue;
        }

        opa->dataValueAddr = result.data->i32;

        result = opa_free(opa, dataAddr);
        if (result.err)
            FATAL("load_opa_data opa_free error: %s", result.err);

        wasm_vm_unlock(opa->vm);
    }

    kfree(data);
}
