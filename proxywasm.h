/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#ifndef proxywasm_h
#define proxywasm_h

#include "runtime.h"

typedef enum {
  WasmResult_Ok = 0,
  // The result could not be found, e.g. a provided key did not appear in a
  // table.
  WasmResult_NotFound = 1,
  // An argument was bad, e.g. did not not conform to the required range.
  WasmResult_BadArgument = 2,
  // A protobuf could not be serialized.
  WasmResult_SerializationFailure = 3,
  // A protobuf could not be parsed.
  WasmResult_ParseFailure = 4,
  // A provided expression (e.g. "foo.bar") was illegal or unrecognized.
  WasmResult_BadExpression = 5,
  // A provided memory range was not legal.
  WasmResult_InvalidMemoryAccess = 6,
  // Data was requested from an empty container.
  WasmResult_Empty = 7,
  // The provided CAS did not match that of the stored data.
  WasmResult_CasMismatch = 8,
  // Returned result was unexpected, e.g. of the incorrect size.
  WasmResult_ResultMismatch = 9,
  // Internal failure: trying check logs of the surrounding system.
  WasmResult_InternalFailure = 10,
  // The connection/stream/pipe was broken/closed unexpectedly.
  WasmResult_BrokenConnection = 11,
  // Feature not implemented.
  WasmResult_Unimplemented = 12,
} WasmResult;

typedef enum {
    HttpRequestBody = 0,
    HttpResponseBody = 1,
    DownstreamData = 2,
    UpstreamData = 3,
    HttpCallResponseBody = 4,
    GrpcReceiveBuffer = 5,
    VmConfiguration = 6,
    PluginConfiguration = 7,
} BufferType;

struct proxywasm;

wasm_vm_result init_proxywasm_for(wasm_vm *vm, const char* module);

wasm_vm_result proxy_on_context_create(struct proxywasm *p, i32 context_id, i32 root_context_id);
wasm_vm_result proxy_on_new_connection(struct proxywasm *p, i32 context_id);

void get_property(struct proxywasm *p, const char *key, int key_len, char **value, int *value_len);
void set_property(struct proxywasm *p, const char *key, int key_len, const char *value, int value_len);
void get_buffer(struct proxywasm *p, BufferType buffer_type, i32 offset, i32 max_size, char **value, i32 *value_len, int *return_flags);

#endif
