# OPA requires floats
EMULATE_FLOATS := 1
EXTRA_CFLAGS := -foptimize-sibling-calls \
				-Dd_m3RecordBacktraces=1 \
				-DDEBUG=1 \
				-Dd_m3HasFloat=$(EMULATE_FLOATS) \
				-I$(PWD) \
				-I$(PWD)/third-party/wasm3/source/ \
				-I$(PWD)/third-party/base64 \
				-I$(PWD)/third-party/parson \
				#-Dd_m3LogCompile=1

# Enable floating point arithmetic
ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
	ifeq ($(EMULATE_FLOATS), 1)
		EXTRA_CFLAGS += -msse4
	endif
# TODO: Otherwise __popcountdi2 is undefined.
# https://stackoverflow.com/questions/52161596/why-is-builtin-popcount-slower-than-my-own-bit-counting-function
	# EXTRA_CFLAGS += -march=native
endif
ifeq ($(ARCH), aarch64)
# TODO: Otherwise __popcountdi2 is undefined.
# https://www.kernel.org/doc/Documentation/kbuild/makefiles.rst
# Anyhow, float emulation works only with this flag removed.
	ccflags-remove-y += -mgeneral-regs-only
endif

ccflags-remove-y += -Wdeclaration-after-statement

VERBOSE := 1

# obj-m specifies we're a kernel module.
obj-m += wasm.o
wasm-objs :=  third-party/wasm3/source/m3_api_libc.o \
              third-party/wasm3/source/m3_compile.o \
			  third-party/wasm3/source/m3_api_meta_wasi.o \
			  third-party/wasm3/source/m3_api_tracer.o \
			  third-party/wasm3/source/m3_api_uvwasi.o \
			  third-party/wasm3/source/m3_api_wasi.o \
			  third-party/wasm3/source/m3_bind.o \
			  third-party/wasm3/source/m3_code.o \
			  third-party/wasm3/source/m3_core.o \
			  third-party/wasm3/source/m3_env.o \
			  third-party/wasm3/source/m3_exec.o \
			  third-party/wasm3/source/m3_function.o \
			  third-party/wasm3/source/m3_info.o \
			  third-party/wasm3/source/m3_module.o \
			  third-party/wasm3/source/m3_parse.o \
			  third-party/base64/base64.o \
			  third-party/parson/json.o \
			  device_driver.o \
			  main.o \
			  netfilter.o \
			  hashtable.o \
			  runtime.o \
			  worker_thread.o \
			  opa.o

# Set the path to the Kernel build utils.
KBUILD=/lib/modules/$(shell uname -r)/build/
 
default:
	$(MAKE) -C $(KBUILD) M=$(PWD) V=$(VERBOSE) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

help:
	$(MAKE) -C $(KBUILD) M=$(PWD) help

logs:
	sudo dmesg -T --follow

insmod:
	sudo insmod wasm.ko

rmmod:
	sudo rmmod wasm
	sudo rm -f /run/wasm.socket

build-dns-hello-world-wasm:
	cd samples/hello-world-rust; make

build-dns-go-wasm:
	cd samples/dns-go; make

build-dns-rust-wasm:
	cd samples/dns-rust; make

load-hello-rust-wasm:
	sudo cli/cli load -file samples/hello-world-rust/target/wasm32-unknown-unknown/release/hello-world.wasm

load-dns-go-wasm:
	sudo cli/cli load -file samples/dns-go/dns-go.wasm

load-dns-rust-wasm:
	sudo cli/cli load -name dns -file samples/dns-rust/target/wasm32-unknown-unknown/release/dns-rust.wasm

load-opa-policy-wasm:
	sudo cli/cli load -name opa -file opa/policy.wasm

build-cli:
	cd cli; go build

setup-vm:
	sudo apt update
	sudo apt install clang libbpf-dev dwarves build-essential linux-tools-generic
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/

setup-archlinux-vm:
	sudo pacman -Syu linux-headers base-devel clang go

opa-bundle:
	opa build -t wasm -e "xdp/allow" opa/xdp.rego -o opa/bundle.tar.gz
	tar zxvf opa/bundle.tar.gz /policy.wasm
	mv policy.wasm opa/

opa-test:
	opa test opa/*.rego -v
