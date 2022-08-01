#ifndef wasm_module_h
#define wasm_module_h

#include "wasm3/source/m3_core.h"
#include "wasm3/source/wasm3.h"

#define FATAL(msg, ...)                                    \
    {                                                      \
        printk("wasm3: Error: [Fatal] " msg "\n", ##__VA_ARGS__); \
    }

typedef struct wasm_vm
{
    spinlock_t _lock;
    unsigned long _lock_flags;
    int cpu;

    IM3Environment _env;
    IM3Runtime _runtime;
} wasm_vm;

typedef struct wasm_vm_result
{
    union
    {
        i32 i32;
        i64 i64;
        f32 f32;
        f64 f64;
    };
    char *err;
} wasm_vm_result;


wasm_vm *wasm_vm_for_cpu(unsigned cpu);
wasm_vm *current_wasm_vm(void);
wasm_vm_result wasm_vm_new_per_cpu(void);
wasm_vm_result wasm_vm_destroy_per_cpu(void);
wasm_vm *wasm_vm_new(int cpu);
void wasm_vm_destroy(wasm_vm *vm);
wasm_vm_result wasm_vm_load_module(wasm_vm *vm, const char *name, unsigned char code[], unsigned code_size);
wasm_vm_result wasm_vm_call(wasm_vm *vm, const char *name, ...);
uint8_t *wasm_vm_memory(wasm_vm *vm);
wasm_vm_result wasm_vm_global(wasm_vm *vm, const char *name);
wasm_vm_result wasm_vm_malloc(wasm_vm *vm, unsigned size);
wasm_vm_result wasm_vm_free(wasm_vm *vm, i32 ptr, unsigned size);
void wasm_vm_set_userdata(wasm_vm *vm, void *userdata);
void wasm_vm_dump_symbols(wasm_vm *vm);
void wasm_vm_lock(wasm_vm *vm);
void wasm_vm_unlock(wasm_vm *vm);

#endif
