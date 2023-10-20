/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include "csr.h"

typedef struct csr_module
{
    wasm_vm *vm;
    // Memory management
    wasm_vm_function *csr_malloc;
    wasm_vm_function *csr_free;
    // Certificate request generation
    wasm_vm_function *generate_csr;
} csr_module;

static csr_module *csr_modules[NR_CPUS] = {0};

csr_module *this_cpu_csr(void)
{
    int cpu = get_cpu();
    put_cpu();
    return csr_modules[cpu];
}

wasm_vm_module *get_csr_module(csr_module *csr)
{
    return csr->csr_malloc->module;
}

void csr_lock(csr_module *csr)
{
    wasm_vm_lock(csr->vm);
}

void csr_unlock(csr_module *csr)
{
    wasm_vm_unlock(csr->vm);
}

wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module)
{
    csr_module *csr = csr_modules[wasm_vm_cpu(vm)];
    if (csr == NULL)
    {
        csr = kzalloc(sizeof(struct csr_module), GFP_KERNEL);
        csr->vm = vm;
        csr_modules[wasm_vm_cpu(vm)] = csr;
    }
    wasm_vm_result result;
    wasm_vm_try_get_function(csr->generate_csr, wasm_vm_get_function(vm, module->name, "csr_gen"));
    wasm_vm_try_get_function(csr->csr_malloc, wasm_vm_get_function(vm, module->name, "csr_malloc"));
    wasm_vm_try_get_function(csr->csr_free, wasm_vm_get_function(vm, module->name, "csr_free"));

error:
    if (result.err)
    {
        pr_crit("csr_module function lookups failed for module %s failed: %s -> %s", module->name, result.err, wasm_vm_last_error(module));
        return result;
    }

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result csr_malloc(csr_module *csr, i32 size)
{
    return wasm_vm_call_direct(csr->vm, csr->csr_malloc, size);
}

wasm_vm_result csr_free(csr_module *csr, i32 ptr)
{
    return wasm_vm_call_direct(csr->vm, csr->csr_free, ptr);
}

// Allocates pointer which is valid inside the wasm module and returns it
static i32 alloc_and_copy_parameter(char *str, i32 str_length, csr_module *csr)
{
    wasm_vm_result malloc_result = csr_malloc(csr, str_length);
    i32 addr;
    if (malloc_result.err)
    {
        pr_err("nasp: malloc_result error: %s", malloc_result.err);
        addr = -1;
        goto bail;
    }
    addr = malloc_result.data->i32;

    strncpy(wasm_vm_memory(get_csr_module(csr)) + addr, str, str_length);
bail:
    return addr;
}

csr_result csr_gen(csr_module *csr, i32 priv_key_buff_ptr, i32 priv_key_buff_len, csr_parameters *parameters)
{
    csr_result result;
// We do not want to concern ourselves with how variadic parameters are handled in wasm; instead,
// we initialize all parameters that are NULL with an empty string.
#define ALLOCATE_AND_CHECK(field)                                                 \
    if (!parameters->field)                                                       \
    {                                                                             \
        parameters->field = "";                                                   \
    }                                                                             \
    i32 field##_len = strlen(parameters->field);                                  \
    i32 field##_ptr;                                                              \
    field##_ptr = alloc_and_copy_parameter(parameters->field, field##_len, csr);  \
    if (field##_ptr == -1)                                                        \
    {                                                                             \
        result.err = "nasp: error during allocating ptr with length for " #field; \
        goto bail;                                                                \
    }

    ALLOCATE_AND_CHECK(subject);
    ALLOCATE_AND_CHECK(dns);
    ALLOCATE_AND_CHECK(uri);
    ALLOCATE_AND_CHECK(email);
    ALLOCATE_AND_CHECK(ip);

    wasm_vm_result vm_result = wasm_vm_call_direct(csr->vm, csr->generate_csr,
                                                   priv_key_buff_ptr, priv_key_buff_len,
                                                   subject_ptr, subject_len,
                                                   dns_ptr, dns_len,
                                                   uri_ptr, uri_len,
                                                   email_ptr, email_len,
                                                   ip_ptr, ip_len);
    if (vm_result.err != NULL)
    {
        pr_err("nasp: calling csr_gen errored %s\n", vm_result.err);
        result.err = vm_result.err;
        goto bail;
    }
    pr_info("nasp: result of calling csr_gen %lld\n", vm_result.data->i64);

    if (vm_result.data->i64 == 0)
    {
        result.err = "csr_gen wasm module returned empty value";
        goto bail;
    }
    result.csr_len = (i32)(vm_result.data->i64);
    result.csr_ptr = (i32)(vm_result.data->i64 >> 32);

bail:
    i32 pointers[] = {subject_ptr, dns_ptr, uri_ptr, email_ptr, ip_ptr};

    int i;
    for (i = 0; i < (sizeof(pointers) / sizeof(pointers[0])); i++)
    {
        if (pointers[i] <= 1)
        {
            continue;
        }
        wasm_vm_result free_result = csr_free(csr, pointers[i]);
        if (free_result.err)
        {
            result.err = free_result.err;
        }
    }
    return result;
}