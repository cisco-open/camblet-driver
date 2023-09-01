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

#define PROXY_WASM "proxywasm"

typedef enum
{
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

typedef enum
{
  HttpRequestBody = 0,
  HttpResponseBody = 1,
  DownstreamData = 2,
  UpstreamData = 3,
  HttpCallResponseBody = 4,
  GrpcReceiveBuffer = 5,
  VmConfiguration = 6,
  PluginConfiguration = 7,
} BufferType;

typedef enum
{
  Continue = 0,
  Pause = 1,
} Action;

typedef enum
{
  ListenerDirectionUnspecified = 0,
  ListenerDirectionInbound = 1,
  ListenerDirectionOutbound = 2,
} ListenerDirection;

typedef enum
{
  Unknown = 0,
  Local = 1,
  Remote = 2,
} PeerType;

typedef struct proxywasm proxywasm;
typedef struct proxywasm_context proxywasm_context;
typedef struct proxywasm_filter proxywasm_filter;

proxywasm *proxywasm_for_vm(wasm_vm *vm);
proxywasm *this_cpu_proxywasm(void);
void proxywasm_lock(proxywasm *p, proxywasm_context *c);
void proxywasm_unlock(proxywasm *p);

wasm_vm_result init_proxywasm_for(wasm_vm *vm, wasm_vm_module *module);

wasm_vm_result proxy_on_context_create(proxywasm *p, i32 context_id, i32 root_context_id);
wasm_vm_result proxy_on_new_connection(proxywasm *p);
wasm_vm_result proxy_on_downstream_data(proxywasm *p, i32 data_size, bool end_of_stream);
wasm_vm_result proxy_on_upstream_data(proxywasm *p, i32 data_size, bool end_of_stream);
wasm_vm_result proxy_on_downstream_connection_close(proxywasm *p, PeerType peer_type);
wasm_vm_result proxy_on_upstream_connection_close(proxywasm *p, PeerType peer_type);

wasm_vm_result proxywasm_create_context(proxywasm *p);
wasm_vm_result proxywasm_destroy_context(proxywasm *p);

proxywasm_context *proxywasm_get_context(proxywasm *p);

// set_property_v is convenience funtion for setting a property on a context, with simple C string paths,
// use the '.' as delimiter, those will be replaced to a '0' delimiter
void set_property_v(proxywasm_context *p, const char *key, const void *value, const int value_len);

// host functions, not needed by the API, just forward declerations
void get_property(proxywasm_context *p, const char *key, int key_len, char **value, int *value_len);
void set_property(proxywasm_context *p, const char *key, int key_len, const char *value, int value_len);
void get_buffer_bytes(proxywasm_context *p, BufferType buffer_type, i32 start, i32 max_size, char **value, i32 *value_len);
WasmResult set_buffer_bytes(proxywasm_context *p, BufferType buffer_type, i32 start, i32 size, char *value, i32 value_len);

char *pw_get_upstream_buffer(proxywasm_context *p);
void pw_set_upstream_buffer(proxywasm_context *p, char *new_buffer);
int pw_get_upstream_buffer_size(proxywasm_context *p);
void pw_set_upstream_buffer_size(proxywasm_context *p, int size);
int pw_get_upstream_buffer_capacity(proxywasm_context *p);
void pw_set_upstream_buffer_capacity(proxywasm_context *p, int capacity);

char *pw_get_downstream_buffer(proxywasm_context *p);
void pw_set_downstream_buffer(proxywasm_context *p, char *new_buffer);
int pw_get_downstream_buffer_size(proxywasm_context *p);
void pw_set_downstream_buffer_size(proxywasm_context *p, int size);
int pw_get_downstream_buffer_capacity(proxywasm_context *p);
void pw_set_downstream_buffer_capacity(proxywasm_context *p, int capacity);

#endif
