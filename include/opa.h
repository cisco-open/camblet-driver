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

#define MAX_ALLOWED_SPIFFE_ID 16

typedef struct
{
    bool allowed;
    bool mtls;
    bool passthrough;
    bool http;
    char *matched_policy_json;
    char *id;
    char *dns;
    char *workload_id;
    bool workload_id_is_valid;
    char *ttl;
    char *allowed_spiffe_ids[MAX_ALLOWED_SPIFFE_ID];
    int allowed_spiffe_ids_length;
    int error;
} opa_socket_context;

void opa_socket_context_free(opa_socket_context ctx);
wasm_vm_result init_opa_for(wasm_vm *vm, wasm_vm_module *module);
opa_socket_context this_cpu_opa_socket_eval(const char *input);
void load_opa_data(const char *data);

#endif
