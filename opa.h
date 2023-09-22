/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#ifndef opa_h
#define opa_h

#include "wasm.h"

#define OPA_MODULE "opa"

typedef struct {
    bool allowed;
    bool mtls;
    bool permissive;
} opa_socket_context;

wasm_vm_result init_opa_for(wasm_vm *vm, wasm_vm_module *module);

int this_cpu_opa_eval(const char *input);
opa_socket_context this_cpu_opa_socket_eval(const char *input);

#endif
