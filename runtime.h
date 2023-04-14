/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#ifndef wasm_module_h
#define wasm_module_h

#include "m3_core.h"
#include "m3_env.h"
#include "m3_exception.h"
#include "wasm3.h"

#define FATAL(msg, ...)                                    \
    {                                                      \
        printk(KERN_CRIT "wasm: Error: [Fatal] " msg "\n", ##__VA_ARGS__); \
    }

// MAX_RETURN_VALUES defines the amount of return values.
// currently only 5 return value supported per function.
#define MAX_RETURN_VALUES 5

typedef struct wasm_vm
{
    spinlock_t _lock;
    unsigned long _lock_flags;
    int cpu;

    IM3Environment _env;
    IM3Runtime _runtime;
} wasm_vm;

typedef struct wasm_vm_result
{
    union
    {
        i32 i32;
        i64 i64;
        f32 f32;
        f64 f64;
    } data[MAX_RETURN_VALUES];
    char *err;
} wasm_vm_result;

typedef M3Module wasm_vm_module;
typedef M3Function wasm_vm_function;

wasm_vm *wasm_vm_for_cpu(unsigned cpu);
wasm_vm *this_cpu_wasm_vm(void);
wasm_vm_result wasm_vm_new_per_cpu(void);
wasm_vm_result wasm_vm_destroy_per_cpu(void);
wasm_vm *wasm_vm_new(int cpu);
void wasm_vm_destroy(wasm_vm *vm);
wasm_vm_result wasm_vm_load_module(wasm_vm *vm, const char *name, unsigned char code[], unsigned code_size);
wasm_vm_result wasm_vm_call(wasm_vm *vm, const char *module, const char *name, ...);
wasm_vm_result wasm_vm_call_direct(wasm_vm *vm, wasm_vm_function *func, ...);
uint8_t *wasm_vm_memory(wasm_vm *vm);
wasm_vm_result wasm_vm_global(wasm_vm *vm, const char *name);
wasm_vm_result wasm_vm_malloc(wasm_vm *vm, const char *module, unsigned size);
wasm_vm_result wasm_vm_free(wasm_vm *vm, const char *module, i32 ptr, unsigned size);
void wasm_vm_set_userdata(wasm_vm *vm, void *userdata);
void wasm_vm_dump_symbols(wasm_vm *vm);
void wasm_vm_lock(wasm_vm *vm);
void wasm_vm_unlock(wasm_vm *vm);
wasm_vm_module *wasm_vm_get_module(wasm_vm *vm, const char *module);
wasm_vm_function *wasm_vm_get_function(wasm_vm *vm, const char *module, const char *function);

M3Result SuppressLookupFailure(M3Result i_result);

#endif
