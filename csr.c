#include <linux/slab.h>
#include "csr.h"

typedef struct csr_module
{
    wasm_vm *vm;

    wasm_vm_function *generate_csr;
}csr_module;

static csr_module *csr_modules[NR_CPUS] = {0};

csr_module* this_cpu_csr(void)
{
    int cpu = get_cpu();
    put_cpu();
    return csr_modules[cpu];
}


wasm_vm_result init_csr_for(wasm_vm *vm, wasm_vm_module *module)
{
    csr_module *csr = csr_modules[vm->cpu];
    if (csr == NULL) {
        csr = kzalloc(sizeof(struct csr_module), GFP_KERNEL);
        csr->vm = vm;
        csr_modules[vm->cpu] = csr;
    }
    wasm_vm_result result;
    wasm_vm_try_get_function(csr->generate_csr, wasm_vm_get_function(vm, module->name, "gen_csr"));

error:
    if (result.err)
    {
        FATAL("csr_module function lookups failed for module %s failed: %s -> %s", module->name, result.err, wasm_vm_last_error(vm));
        return result;
    }

    return (wasm_vm_result){.err = NULL};
}

wasm_vm_result gen_csr(csr_module *csr, i32 priv_key_buff_ptr, i32 priv_key_buff_len) {
    wasm_vm_result result = wasm_vm_call_direct(csr->vm, csr->generate_csr, priv_key_buff_ptr, priv_key_buff_len);
    if (result.err != NULL)
    {
        pr_err("wasm: calling gen_csr errored %s\n", result.err);
        return result;
    }
    printk("wasm: result of calling gen_csr %d\n", result.data->i32);
    return result;
}