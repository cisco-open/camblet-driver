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

enum WasmResult {
  Ok = 0,
  // The result could not be found, e.g. a provided key did not appear in a
  // table.
  NotFound = 1,
  // An argument was bad, e.g. did not not conform to the required range.
  BadArgument = 2,
  // A protobuf could not be serialized.
  SerializationFailure = 3,
  // A protobuf could not be parsed.
  ParseFailure = 4,
  // A provided expression (e.g. "foo.bar") was illegal or unrecognized.
  BadExpression = 5,
  // A provided memory range was not legal.
  InvalidMemoryAccess = 6,
  // Data was requested from an empty container.
  Empty = 7,
  // The provided CAS did not match that of the stored data.
  CasMismatch = 8,
  // Returned result was unexpected, e.g. of the incorrect size.
  ResultMismatch = 9,
  // Internal failure: trying check logs of the surrounding system.
  InternalFailure = 10,
  // The connection/stream/pipe was broken/closed unexpectedly.
  BrokenConnection = 11,
  // Feature not implemented.
  Unimplemented = 12,
};

wasm_vm_result init_proxywasm_for(wasm_vm *vm, const char* module);

#endif
