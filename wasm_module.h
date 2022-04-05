#ifndef wasm_module_h
#define wasm_module_h

#include "wasm3/source/wasm3.h"

#define FATAL(msg, ...)                                    \
    {                                                      \
        printk("Error: [Fatal] " msg "\n", ##__VA_ARGS__); \
    }

M3Result repl_load(const char *module_name, unsigned char wasm_code[], unsigned int wasm_code_size);
M3Result repl_call(const char *name, int argc, const char *argv[]);

#endif
