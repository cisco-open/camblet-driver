# OPA requires floats
EMULATE_FLOATS := 1
EXTRA_CFLAGS := -foptimize-sibling-calls \
				-Dd_m3RecordBacktraces=1 \
				-DDEBUG=1 \
				-Dd_m3HasFloat=$(EMULATE_FLOATS) \
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
wasm-objs :=  wasm3/source/m3_api_libc.o \
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
			  base64.o \
			  device_driver.o \
			  json.o \
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

ALPINE_VERSION ?= 3.13
build-in-docker:
	docker build -t builder -f Dockerfile.dev --build-arg KERNEL_VERSION=$(shell docker info -f "{{ json .KernelVersion }}" | tr -d '"' | cut -d '-' -f 1) --build-arg ALPINE_VERSION=${ALPINE_VERSION} .
	docker run -ti --rm -v $(shell pwd):/workspace -v /dev:/dev -v /run/guest-services:/run/guest-services -v /lib/modules:/lib/modules --privileged builder

insmod-in-docker:
	insmod /workspace/wasm.ko sock_path=/run/guest-services/wasm.socket

insmod:
	sudo insmod wasm.ko

rmmod:
	sudo rmmod wasm
	sudo rm -f /run/wasm.socket

load-dns-go-wasm:
	sudo cli/cli load samples/dns-go.wasm

load-dns-rust-wasm:
	sudo cli/cli load -name dns samples/target/wasm32-unknown-unknown/release/dns-rust.wasm

load-opa-policy-wasm:
	sudo cli/cli load -name opa opa/policy.wasm

build-cli:
	export GOOS=linux; cd cli; go build

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
