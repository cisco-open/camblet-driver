#ifndef opa_h
#define opa_h

#include "runtime.h"

#define OPA_MODULE "opa"

wasm_vm_result init_opa_for(wasm_vm *vm);

int this_cpu_opa_eval(int protocol);

#endif
