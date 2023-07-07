#include "runtime.h"

#define CSR_MODULE "csr"

typedef struct csr_module csr_module;

wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module);
wasm_vm_result gen_csr(wasm_vm *vm, i32 priv_key_buff_ptr, i32 priv_key_buff_len);