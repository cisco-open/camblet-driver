#ifndef wasm_module_h
#define wasm_module_h

#include "wasm3/source/m3_core.h"
#include "wasm3/source/wasm3.h"

#define STACK_SIZE_BYTES 256 * 1024

#define FATAL(msg, ...)                                    \
    {                                                      \
        printk("wasm3: Error: [Fatal] " msg "\n", ##__VA_ARGS__); \
    }

M3Result repl_init(unsigned stack);
void repl_free(void);
M3Result repl_load(const char *module_name, unsigned char wasm_code[], unsigned int wasm_code_size);
M3Result repl_call(const char *name, int argc, const char *argv[]);
i32 repl_call_i32(const char *name, int argc, const char *argv[]);
uint8_t* repl_get_memory(void);
uint64_t repl_global_get(const char* name);
i32 wasm_malloc(unsigned size);
void wasm_free(i32 ptr, unsigned size);

#endif
