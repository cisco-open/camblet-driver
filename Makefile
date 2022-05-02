# TODO: Otherwise __popcountdi2 is undefined.
# https://stackoverflow.com/questions/52161596/why-is-builtin-popcount-slower-than-my-own-bit-counting-function
EXTRA_CFLAGS := -march=native

# obj-m specifie we're a kernel module.
obj-m += wasm3.o
wasm3-objs := wasm3/source/m3_api_libc.o \
              wasm3/source/m3_compile.o \
			  wasm3/source/m3_api_meta_wasi.o \
			  wasm3/source/m3_api_tracer.o \
			  wasm3/source/m3_api_uvwasi.o \
			  wasm3/source/m3_api_wasi.o \
			  wasm3/source/m3_bind.o \
			  wasm3/source/m3_code.o \
			  wasm3/source/m3_core.o \
			  wasm3/source/m3_env.o \
			  wasm3/source/m3_exec.o \
			  wasm3/source/m3_function.o \
			  wasm3/source/m3_info.o \
			  wasm3/source/m3_module.o \
			  wasm3/source/m3_parse.o \
			  wasm_module.o \
			  device_driver.o \
			  netfilter.o \
			  worker_thread.o

# Set the path to the Kernel build utils.
KBUILD=/lib/modules/$(shell uname -r)/build/
 
default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

menuconfig:
	$(MAKE) -C $(KBUILD) M=$(PWD) menuconfig
