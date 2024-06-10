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

#include "opa.h"
#include "json.h"
#include "string.h"
#include "config.h"
#include "spiffe.h"

typedef struct opa_wrapper
{
    wasm_vm *vm;
    wasm_vm_function *malloc;
    wasm_vm_function *free;
    wasm_vm_function *eval;
    wasm_vm_function *json_dump;
    wasm_vm_function *value_dump;
    wasm_vm_function *json_parse;
    wasm_vm_function *heap_ptr_get;
    wasm_vm_function *heap_ptr_set;
    wasm_vm_function *heap_stash_clear;
    wasm_vm_function *heap_blocks_stash;
    void **builtins;

    i32 baseHeapAddr;
    i32 evalHeapAddr;
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

static wasm_vm_result opa_heap_ptr_get(opa_wrapper *opa)
{
    return wasm_vm_call_direct(opa->vm, opa->heap_ptr_get);
}

static wasm_vm_result opa_heap_ptr_set(opa_wrapper *opa, i32 ptr)
{
    return wasm_vm_call_direct(opa->vm, opa->heap_ptr_set, ptr);
}

static wasm_vm_result opa_heap_stash_clear(opa_wrapper *opa)
{
    return wasm_vm_call_direct(opa->vm, opa->heap_stash_clear);
}

static wasm_vm_result opa_heap_block_stash(opa_wrapper *opa)
{
    return wasm_vm_call_direct(opa->vm, opa->heap_blocks_stash);
}

static wasm_vm_result opa_json_parse(opa_wrapper *opa, i32 dataAddr, i32 dataLen)
{
    return wasm_vm_call_direct(opa->vm, opa->json_parse, dataAddr, dataLen);
}

static i32 opa_set_data_from_json(opa_wrapper *opa, const char *data, bool free)
{
    i32 dataValueAddr = 0;
    int dataLen = strlen(data);

    wasm_vm_result result = opa_malloc(opa, dataLen);
    if (result.err)
    {
        pr_crit("wasm malloc error # err[%s]", result.err);
        return -1;
    }

    i32 dataAddr = result.data->i32;
    memcpy(wasm_vm_memory(opa->json_parse->module) + dataAddr, data, dataLen);

    result = opa_json_parse(opa, dataAddr, dataLen);
    if (result.err)
    {
        pr_crit("wasm json parse error # err[%s]", result.err);
        goto cleanup;
    }

    dataValueAddr = result.data->i32;

cleanup:
    if (free)
    {
        result = opa_free(opa, dataAddr);
        if (result.err)
        {
            pr_crit("wasm free error # err[%s]", result.err);
            return -1;
        }
    }

    return dataValueAddr;
}

static int opa_set_data(opa_wrapper *opa, const char *data)
{
    wasm_vm_result result = opa_heap_stash_clear(opa);
    if (result.err)
    {
        pr_crit("wasm opa_heap_stash_clear error # err[%s]", result.err);
        return -1;
    }

    result = opa_heap_ptr_set(opa, opa->baseHeapAddr);
    if (result.err)
    {
        pr_crit("wasm opa_heap_ptr_set error # err[%s]", result.err);
        return -1;
    }

    // json
    i32 dataValueAddr = opa_set_data_from_json(opa, data, true);
    if (dataValueAddr <= 0)
    {
        return -1;
    }
    opa->dataValueAddr = dataValueAddr;

    result = opa_heap_block_stash(opa);
    if (result.err)
    {
        pr_crit("wasm opa_heap_block_stash error # err[%s]", result.err);
        return -1;
    }

    result = opa_heap_ptr_get(opa);
    if (result.err)
    {
        pr_crit("wasm opa_heap_ptr_get error # err[%s]", result.err);
        return -1;
    }

    opa->evalHeapAddr = result.data->i32;

    return 0;
}

static wasm_vm_result opa_eval(opa_wrapper *opa, i32 inputAddr, i32 inputLen, i32 dataValueAddr, i32 heapAddr)
{
    i32 entrypoint = 0;
    i32 format = 0; // 0 is JSON, 1 is “value”, i.e. serialized Rego values

    return wasm_vm_call_direct(opa->vm, opa->eval, 0, entrypoint, dataValueAddr, inputAddr, inputLen, heapAddr, format);
}

opa_wrapper *this_cpu_opa(void)
{
    int cpu = get_cpu();
    put_cpu();
    return opas[cpu];
}

static i32 builtin_time_now_ns(opa_wrapper *opa, i32 _ctx)
{
    u64 now = ktime_get_real_ns();

    wasm_vm_result result = opa_malloc(opa, sizeof(now));
    if (result.err)
    {
        pr_crit("wasm malloc error # err[%s]", result.err);
        return 0;
    }

    uint8_t *mem = wasm_vm_memory(opa->eval->module);
    i32 addr = result.data->i32;

    memcpy(mem + addr, &now, sizeof(now));

    return addr;
}

static i32 builtin_trace(opa_wrapper *opa, i32 _ctx, i32 arg1)
{
    uint8_t *mem = wasm_vm_memory(opa->eval->module);

    wasm_vm_result result = wasm_vm_call_direct(opa->vm, opa->value_dump, arg1);
    if (result.err)
    {
        pr_crit("wasm value_dump error # err[%s]", result.err);
        return 0;
    }

    pr_debug("opa note # note[%s]", (char *)(mem + result.data->i32));

    result = opa_malloc(opa, sizeof(true));
    if (result.err)
    {
        pr_crit("wasm malloc error # err[%s]", result.err);
        return 0;
    }

    i32 addr = result.data->i32;

    int true = true;

    memcpy(mem + addr, &true, sizeof(true));

    return addr;
}

static wasm_vm_result parse_opa_builtins(opa_wrapper *opa, char *json)
{
    JSON_Value *root_value = json_parse_string(json);
    if (root_value)
    {
        wasm_vm_result result = wasm_vm_ok;
        JSON_Object *object = json_object(root_value);
        int builtin_count = json_object_get_count(object);
        pr_debug("opa builtins # json[%s]", json);

        if (builtin_count == 0)
            goto bail;

        // indexing starts from 1 for some reason, so we need one bigger array
        opa->builtins = kzalloc(builtin_count + 1 * sizeof(void *), GFP_KERNEL);
        if (!opa->builtins)
        {
            result = wasm_vm_error("could not allocate memory");
            goto bail;
        }

        int i;
        for (i = 0; i < builtin_count; i++)
        {
            const char *name = json_object_get_name(object, i);
            const int64_t builtin_id = json_object_get_number(object, name);

            if (strcmp(name, "time.now_ns") == 0)
            {
                opa->builtins[builtin_id] = builtin_time_now_ns;
            }
            else if (strcmp(name, "trace") == 0)
            {
                opa->builtins[builtin_id] = builtin_trace;
            }
            else
            {
                result = wasm_vm_error("unsupported opa builtin function");
                snprintf(opa->malloc->module->runtime->error_message, 256, "unsupported opa builtin function: %s", name);
                kfree(opa->builtins);

                goto bail;
            }
        }

    bail:
        json_value_free(root_value);

        return result;
    }

    return wasm_vm_error("could not parse opa builtins");
}

void opa_socket_context_free(opa_socket_context ctx)
{
    kfree(ctx.matched_policy_json);
    kfree(ctx.id);
    kfree(ctx.dns);
    kfree(ctx.workload_id);
    kfree(ctx.ttl);

    int i;
    for (i = 0; i < ctx.allowed_spiffe_ids_length; i++)
    {
        kfree(ctx.allowed_spiffe_ids[i]);
    }
}

opa_socket_context parse_opa_socket_eval_result(char *json)
{
    JSON_Value *root_value = NULL;
    opa_socket_context ret = {0};

    root_value = json_parse_string(json);
    if (!root_value)
    {
        ret.error = -EINVAL;
        return ret;
    }
    else
    {
        JSON_Array *results = json_value_get_array(root_value);
        JSON_Object *result = json_array_get_object(results, 0);
        if (!result)
        {
            ret.error = -EINVAL;
            goto free;
        }

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
            int pos = json_object_get_number(policy, "position");
            if (pos < policy_prio || policy_prio == -1)
            {
                policy_prio = pos;
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
            int pos = json_object_get_number(policy, "position");
            if (pos != policy_prio)
            {
                continue;
            }
            int egress_pos = json_object_dotget_number(policy, "egress.position");
            if (egress_pos < egress_prio || egress_prio == -1)
            {
                egress_prio = egress_pos;
                matched_policy = policy;
            }
        }

        ret.matched_policy_json = json_serialize_to_string(json_object_get_wrapping_value(matched_policy));
        pr_debug("policy match # policy[%s] prio[%d] egress_prio[%d]", ret.matched_policy_json, policy_prio, egress_prio);

        const char *ttl = json_object_dotget_string(matched_policy, "egress.certificate.ttl");
        if (ttl == NULL)
            ttl = json_object_dotget_string(matched_policy, "certificate.ttl");
        if (ttl != NULL)
        {
            ret.ttl = kstrdup(ttl, GFP_KERNEL);
            if (!ret.ttl)
            {
                ret.error = -ENOMEM;
                goto free;
            }
        }

        size_t egress_id_len = json_object_dotget_string_len(matched_policy, "egress.id");
        size_t id_len = json_object_dotget_string_len(matched_policy, "id");
        if (egress_id_len > 0 || id_len > 0)
        {
            size_t ttl_len = 0;
            if (ttl)
            {
                ttl_len = strlen(ttl);
            }

            camblet_config_lock();
            camblet_config *config = camblet_config_get_locked();
            size_t trust_domain_len = strlen(config->trust_domain);
            ret.id = kzalloc(egress_id_len + id_len + trust_domain_len + ttl_len + 1, GFP_KERNEL);
            if (!ret.id)
            {
                ret.error = -ENOMEM;
                goto free;
            }
            strcat(ret.id, config->trust_domain);
            camblet_config_unlock();

            if (ttl_len > 0)
            {
                strcat(ret.id, ttl);
            }
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
        ret.passthrough = false;
        ret.http = false;

        JSON_Array *allowed_spiffe_ids = json_object_dotget_array(matched_policy, "egress.connection.allowedSPIFFEIDs");
        if (allowed_spiffe_ids == NULL)
            allowed_spiffe_ids = json_object_dotget_array(matched_policy, "connection.allowedSPIFFEIDs");
        if (allowed_spiffe_ids != NULL)
        {
            ret.allowed_spiffe_ids_length = json_array_get_count(allowed_spiffe_ids);
            for (i = 0; i < ret.allowed_spiffe_ids_length; i++)
            {
                ret.allowed_spiffe_ids[i] = kstrdup(json_array_get_string(allowed_spiffe_ids, i), GFP_KERNEL);
                if (!ret.allowed_spiffe_ids[i])
                {
                    ret.error = -ENOMEM;
                    goto free;
                }
            }
        }

        const char *mtls = json_object_dotget_string(matched_policy, "egress.connection.mtls");
        if (mtls == NULL)
            mtls = json_object_dotget_string(matched_policy, "connection.mtls");

        if (mtls != NULL && strcmp(mtls, "DISABLE") == 0)
            ret.mtls = false;

        int passthrough = json_object_dotget_boolean(matched_policy, "egress.connection.passthrough");
        if (passthrough == -1)
            passthrough = json_object_dotget_boolean(matched_policy, "connection.passthrough");
        if (passthrough == 0)
            ret.passthrough = false;
        else if (passthrough == 1)
            ret.passthrough = true;

        int http = json_object_dotget_boolean(matched_policy, "egress.connection.http");
        if (http == -1)
            http = json_object_dotget_boolean(matched_policy, "connection.http");
        if (http == 0)
            ret.http = false;
        else if (http == 1)
            ret.http = true;

        const char *workload_id = json_object_dotget_string(matched_policy, "egress.certificate.workloadID");
        if (workload_id == NULL)
            workload_id = json_object_dotget_string(matched_policy, "certificate.workloadID");
        if (workload_id != NULL)
        {
            camblet_config_lock();
            camblet_config *config = camblet_config_get_locked();
            int workload_id_len = snprintf(NULL, 0, "spiffe://%s/%s", config->trust_domain, workload_id);
            ret.workload_id = kzalloc(workload_id_len + 1, GFP_KERNEL);
            if (!ret.workload_id)
            {
                ret.error = -ENOMEM;
                goto free;
            }
            snprintf(ret.workload_id, workload_id_len + 1, "spiffe://%s/%s", config->trust_domain, workload_id);
            camblet_config_unlock();
        }

        ret.workload_id_is_valid = is_spiffe_id_valid(ret.workload_id);

        JSON_Array *dns = json_object_dotget_array(matched_policy, "egress.certificate.dnsNames");
        if (dns == NULL)
            dns = json_object_dotget_array(matched_policy, "certificate.dnsNames");
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
            if (!ret.dns)
            {
                ret.error = -ENOMEM;
                goto free;
            }
            for (i = 0; i < json_array_get_count(dns); i++)
            {
                strcat(ret.dns, json_array_get_string(dns, i));
                if (i < json_array_get_count(dns) - 1)
                {
                    strcat(ret.dns, ",");
                }
            }
        }

    free:
        json_value_free(root_value);
    }

    return ret;
}

static size_t get_memory_page_count(size_t size)
{
    size_t pages = size / d_m3MemPageSize;

    if (pages * d_m3MemPageSize == size)
    {
        return pages;
    }

    return pages + 1;
}

m3ApiRawFunction(opa_abort)
{
    m3ApiGetArgMem(char *, addr);
    pr_err("opa abort # addr[%s]", addr);
    m3ApiTrap(m3Err_trapAbort);
}

m3ApiRawFunction(opa_println)
{
    m3ApiGetArgMem(char *, addr);
    pr_info("%s", addr);
    m3ApiSuccess();
}

m3ApiRawFunction(opa_builtin0)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    pr_debug("call opa_builtin0 # id[%d]", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("opa_builtin0 not found # id[%d]", builtin_id);
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

    pr_debug("call opa_builtin1 # id[%d]", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("opa_builtin1 not found # id[%d]", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx, _1));
}

m3ApiRawFunction(opa_builtin2)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);
    m3ApiGetArg(i32, _1);
    m3ApiGetArg(i32, _2);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    pr_debug("call opa_builtin2 # id[%d]", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32, i32, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("opa_builtin2 not found # id[%d]", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx, _1, _2));
}

m3ApiRawFunction(opa_builtin3)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);
    m3ApiGetArg(i32, _1);
    m3ApiGetArg(i32, _2);
    m3ApiGetArg(i32, _3);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    pr_debug("call opa_builtin3 # id[%d]", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32, i32, i32, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("opa_builtin3 not found # id[%d]", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx, _1, _2, _3));
}

m3ApiRawFunction(opa_builtin4)
{
    m3ApiReturnType(i32);

    m3ApiGetArg(i32, builtin_id);
    m3ApiGetArg(i32, ctx);
    m3ApiGetArg(i32, _1);
    m3ApiGetArg(i32, _2);
    m3ApiGetArg(i32, _3);
    m3ApiGetArg(i32, _4);

    opa_wrapper *opa = (opa_wrapper *)_ctx->userdata;

    pr_debug("call opa_builtin4 # id[%d]", builtin_id);

    i32 (*builtin)(opa_wrapper *, i32, i32, i32, i32, i32) = opa->builtins[builtin_id];

    if (!builtin)
    {
        pr_err("opa_builtin4 not found # id[%d]", builtin_id);
        m3ApiTrap(m3Err_trapAbort);
    }

    m3ApiReturn(builtin(opa, ctx, _1, _2, _3, _4));
}

static wasm_vm_result link_opa_host_functions(opa_wrapper *opa, wasm_vm_module *module)
{
    M3Result result = m3Err_none;

    const char *env = "env";

    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_abort", "(i)", opa_abort, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_println", "(i)", opa_println, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin0", "i(ii)", opa_builtin0, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin1", "i(iii)", opa_builtin1, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin2", "i(iiii)", opa_builtin2, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin3", "i(iiiii)", opa_builtin3, opa)));
    _(SuppressLookupFailure(m3_LinkRawFunctionEx(module, env, "opa_builtin4", "i(iiiiii)", opa_builtin4, opa)));

_catch:
    return (wasm_vm_result){.err = result};
}

wasm_vm_result init_opa_for(wasm_vm *vm, wasm_vm_module *module)
{
    wasm_vm_result result;
    wasm_vm_function *builtinsFunc;

    opa_wrapper *opa = kzalloc(sizeof(struct opa_wrapper), GFP_KERNEL);
    if (!opa)
    {
        return wasm_vm_error("could not allocate memory");
    }
    wasm_vm_try_get_function(opa->malloc, wasm_vm_get_function(vm, module->name, "opa_malloc"));
    wasm_vm_try_get_function(opa->free, wasm_vm_get_function(vm, module->name, "opa_free"));
    wasm_vm_try_get_function(opa->eval, wasm_vm_get_function(vm, module->name, "opa_eval"));
    wasm_vm_try_get_function(opa->json_dump, wasm_vm_get_function(vm, module->name, "opa_json_dump"));
    wasm_vm_try_get_function(opa->value_dump, wasm_vm_get_function(vm, module->name, "opa_value_dump"));
    wasm_vm_try_get_function(builtinsFunc, wasm_vm_get_function(vm, module->name, "builtins"));
    wasm_vm_try_get_function(opa->json_parse, wasm_vm_get_function(vm, module->name, "opa_json_parse"));

    wasm_vm_try_get_function(opa->heap_ptr_get, wasm_vm_get_function(vm, module->name, "opa_heap_ptr_get"));
    wasm_vm_try_get_function(opa->heap_ptr_set, wasm_vm_get_function(vm, module->name, "opa_heap_ptr_set"));
    wasm_vm_try_get_function(opa->heap_stash_clear, wasm_vm_get_function(vm, module->name, "opa_heap_stash_clear"));
    wasm_vm_try_get_function(opa->heap_blocks_stash, wasm_vm_get_function(vm, module->name, "opa_heap_blocks_stash"));

    opa->vm = vm;

    result = opa_malloc(opa, 0);
    if (result.err)
        goto error;

    result = opa_heap_ptr_get(opa);
    if (result.err)
        goto error;
    opa->baseHeapAddr = result.data->i32;

    result = wasm_vm_call_direct(vm, builtinsFunc);
    if (result.err)
        goto error;

    result = wasm_vm_call_direct(vm, opa->json_dump, result.data->i32);
    if (result.err)
        goto error;
    i32 builtinsJson = result.data->i32;

    // parse and link
    char *builtins = wasm_vm_memory(opa->eval->module) + builtinsJson;
    result = parse_opa_builtins(opa, builtins);
    if (result.err)
    {
        goto error;
    }

    opa_free(opa, builtinsJson);

    result = link_opa_host_functions(opa, module);
    if (result.err)
    {
        goto error;
    }

    opas[wasm_vm_cpu(vm)] = opa;

error:
    if (result.err)
    {
        kfree(opa);
        return result;
    }

    return wasm_vm_ok;
}

opa_socket_context this_cpu_opa_socket_eval(const char *input)
{
    opa_socket_context ret = {0};
    i32 heapAddr = 0;
    i32 inputAddr = 0;
    i32 inputLen = strlen(input);
    wasm_vm_result result;

    opa_wrapper *opa = this_cpu_opa();

    if (!opa)
    {
        pr_warn("opa socket policy module not loaded: eval always evaluates to NULL");

        return ret;
    }

    pr_debug("opa eval # name[%s] input[%s]", opa->eval->module->name, input);

    wasm_vm_lock(opa->vm);

    heapAddr = opa->evalHeapAddr;
    inputAddr = opa->evalHeapAddr;

    uint32_t memorySize = m3_GetMemorySize(opa->eval->module->runtime);

    int rest = inputAddr + inputLen - memorySize;
    if (rest > 0) // need to grow memory
    {
        M3Result m3result = ResizeMemory(opa->eval->module->runtime, get_memory_page_count(memorySize + rest));
        if (m3result)
        {
            pr_crit("could not grow wasm module memory");
            goto cleanup;
        }
    }

    memcpy(wasm_vm_memory(opa->eval->module) + inputAddr, input, inputLen);
    heapAddr += inputLen;

    result = opa_eval(opa, inputAddr, inputLen, opa->dataValueAddr, heapAddr);
    if (result.err)
    {
        pr_crit("opa eval error # name[%s] err[%s: %s]", opa->eval->module->name, result.err, wasm_vm_last_error(opa->eval->module));
        goto cleanup;
    }

    char *json = (char *)(wasm_vm_memory(opa->eval->module) + result.data->i32);
    ret = parse_opa_socket_eval_result(json);

cleanup:
    wasm_vm_unlock(opa->vm);

    return ret;
}

void load_opa_data(const char *data)
{
    unsigned cpu;

    for_each_online_cpu(cpu)
    {
        opa_wrapper *opa = opas[cpu];
        wasm_vm_lock(opa->vm);
        int ret = opa_set_data(opa, data);
        wasm_vm_unlock(opa->vm);
        if (ret < 0)
        {
            pr_err("could not set opa data");
        }
    }
}

void free_opa_modules(void)
{
    unsigned cpu;

    for_each_online_cpu(cpu)
    {
        opa_wrapper *opa = opas[cpu];
        if (opa)
        {
            kfree(opa->builtins);
            kfree(opa);
            opas[cpu] = NULL;
        }
    }
}
