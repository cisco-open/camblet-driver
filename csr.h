#include "runtime.h"

#define CSR_MODULE "csr"

typedef struct csr_module csr_module;

csr_module *this_cpu_csr(void);

wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module);
wasm_vm_result csr_gen(csr_module *csr, i32 priv_key_buff_ptr, i32 priv_key_buff_len);
wasm_vm_result csr_malloc(csr_module *csr, i32 size);
wasm_vm_result csr_free(csr_module *csr, i32 ptr);
wasm_vm_module *get_csr_module(csr_module *csr);
void csr_lock(csr_module *csr);
void csr_unlock(csr_module *csr);