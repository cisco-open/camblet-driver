#include "runtime.h"

#define CSR_MODULE "csr"

typedef struct csr_module csr_module;

csr_module *this_cpu_csr(void);

wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module);
wasm_vm_result gen_csr(csr_module *csr, i32 priv_key_buff_ptr, i32 priv_key_buff_len);