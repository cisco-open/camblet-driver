#include <linux/slab.h>
#include "csr.h"

typedef struct csr_module
{
wasm_vm_function *gen_csr;
}csr_module;

wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module)
{
    wasm_vm_result result;
    csr_module *csr = kzalloc(sizeof(csr_module), GFP_KERNEL);

    wasm_vm_try_get_function(csr->gen_csr, wasm_vm_get_function(vm, module->name, "gen_csr"));

error:
    if (result.err)
    {
        FATAL("csr_module function lookups failed for module %s failed: %s -> %s", module->name, result.err, wasm_vm_last_error(vm));
        return result;
    }

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result gen_csr(wasm_vm *vm, i32 priv_key_buff_ptr, i32 priv_key_buff_len) {
    wasm_vm_result result = wasm_vm_call_direct(vm, gen_csr, priv_key_buff_ptr, priv_key_buff_len);
    if (result.err != NULL)
    {
        pr_err("wasm: calling gen_csr errored %s\n", result.err);
        return result;
    }
    printk("wasm: result of calling gen_csr %d\n", result.data->i32);
    return result;
}