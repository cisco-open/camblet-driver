/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#ifndef wasm_h
#define wasm_h

#include "m3_core.h"
#include "m3_env.h"
#include "m3_exception.h"
#include "wasm3.h"

#define FATAL(msg, ...)                                                    \
    {                                                                      \
        printk(KERN_CRIT "camblet: Error: [Fatal] " msg "\n", ##__VA_ARGS__); \
    }

#define PRIi32 "i"
#define PRIi64 "lli"

#define MAX_MODULES_PER_VM 16

// MAX_RETURN_VALUES defines the amount of return values.
#define MAX_RETURN_VALUES 3

#define STACK_SIZE_BYTES 256 * 1024

typedef struct wasm_vm wasm_vm;

typedef M3Module wasm_vm_module;
typedef M3Function wasm_vm_function;

typedef struct wasm_vm_result
{
    union
    {
        i32 i32;
        i64 i64;
        f32 f32;
        f64 f64;
        wasm_vm_module *module;
        wasm_vm_function *function;
    } data[MAX_RETURN_VALUES];
    const char *err;
} wasm_vm_result;

extern const wasm_vm_result wasm_vm_result_ok;

#define wasm_vm_try_get_function(VAR, CALL) \
    {                                       \
        result = CALL;                      \
        if (result.err)                     \
            goto error;                     \
        VAR = result.data->function;        \
    }

wasm_vm *wasm_vm_for_cpu(unsigned cpu);
wasm_vm *this_cpu_wasm_vm(void);
wasm_vm_result wasm_vm_new_per_cpu(void);
wasm_vm_result wasm_vm_destroy_per_cpu(void);
wasm_vm *wasm_vm_new(int cpu);
void wasm_vm_destroy(wasm_vm *vm);
int wasm_vm_cpu(wasm_vm *vm);
wasm_vm_result wasm_vm_load_module(wasm_vm *vm, const char *name, unsigned char code[], unsigned code_size);
wasm_vm_result wasm_vm_call(wasm_vm *vm, const char *module, const char *name, ...);
wasm_vm_result wasm_vm_call_direct(wasm_vm *vm, wasm_vm_function *func, ...);
uint8_t *wasm_vm_memory(wasm_vm_module *module);
wasm_vm_result wasm_vm_global(wasm_vm_module *module, const char *name);
wasm_vm_result wasm_vm_malloc(wasm_vm *vm, const char *module, unsigned size);
wasm_vm_result wasm_vm_free(wasm_vm *vm, const char *module, i32 ptr, unsigned size);
void wasm_vm_set_userdata(wasm_vm *vm, void *userdata);
void wasm_vm_dump_symbols(wasm_vm *vm);
void wasm_vm_lock(wasm_vm *vm);
void wasm_vm_unlock(wasm_vm *vm);
wasm_vm_result wasm_vm_get_module(wasm_vm *vm, const char *module);
wasm_vm_result wasm_vm_get_function(wasm_vm *vm, const char *module, const char *function);
const char *wasm_vm_last_error(wasm_vm_module *module);

M3Result SuppressLookupFailure(M3Result i_result);

#endif
