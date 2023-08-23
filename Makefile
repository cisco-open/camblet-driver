# OPA requires floats
EMULATE_FLOATS := 1
ccflags-y += -foptimize-sibling-calls \
			 -Dd_m3RecordBacktraces=1 \
			 -DDEBUG=1 \
			 -Dd_m3HasFloat=$(EMULATE_FLOATS) \
			 -I$(PWD) \
			 -I$(PWD)/third-party/BearSSL/inc/ \
			 -I$(PWD)/third-party/wasm3/source/ \
			 -I$(PWD)/third-party/base64 \
			 -I$(PWD)/third-party/parson \
			 #-Dd_m3LogCompile=1

# Enable floating point arithmetic
ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
	ifeq ($(EMULATE_FLOATS), 1)
		ccflags-remove-y += -mno-sse -mno-sse2
	endif

	# TODO: Otherwise __popcountdi2 is undefined.
	# https://stackoverflow.com/questions/52161596/why-is-builtin-popcount-slower-than-my-own-bit-counting-function
	# ccflags-y += -march=native
endif
ifeq ($(ARCH), aarch64)
# TODO: Otherwise __popcountdi2 is undefined.
# https://www.kernel.org/doc/Documentation/kbuild/makefiles.rst
# Anyhow, float emulation works only with this flag removed.
	ccflags-remove-y += -mgeneral-regs-only
endif

KBUILD_EXTRA_SYMBOLS = $(PWD)/third-party/BearSSL/Module.symvers

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
			  csr.o \
			  rsa_tools.o \
			  runtime.o \
			  worker_thread.o \
			  opa.o \
			  proxywasm.o \
			  socket.o \
			  task_context.o \
			  commands.o

# Set the path to the Kernel build utils.
KBUILD=/lib/modules/$(shell uname -r)/build/

default: socket_wasm.h
	cd third-party/BearSSL && $(MAKE) linux-km
	$(MAKE) -C $(KBUILD) M=$(PWD) V=$(VERBOSE) modules

socket_wasm.h: socket.rego
	opa build -t wasm -e "socket/allow" socket.rego -o bundle.tar.gz
	tar zxvf bundle.tar.gz /policy.wasm
	mv policy.wasm socket.wasm
	xxd -i socket.wasm socket_wasm.h

opa-test:
	opa test *.rego -v

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

help:
	$(MAKE) -C $(KBUILD) M=$(PWD) help

logs:
	sudo dmesg -T --follow

insmod-bearssl:
	sudo insmod third-party/BearSSL/bearssl.ko

insmod: insmod-bearssl
	sudo modprobe tls
	sudo insmod wasm.ko

insmod-no-proxywasm: insmod-bearssl
	sudo insmod wasm.ko proxywasm_modules=0

rmmod:
	sudo rmmod wasm
	sudo rm -f /run/wasm.socket
	sudo rmmod bearssl

_debian_deps:
	sudo apt update
	sudo apt install -y clang libbpf-dev dwarves build-essential linux-tools-generic golang dkms flex bison

_archlinux_deps:
	sudo pacman -Syu linux-headers base-devel clang go dkms git strace bc

_install_opa:
	sudo curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.54.0/opa_linux_$(shell go version | cut -f2 -d'/')_static
	sudo chmod +x /usr/local/bin/opa

setup-vm: _debian_deps _install_opa
	sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/

setup-archlinux-vm: _archlinux_deps _install_opa

setup-dev-env:
	test -f .vscode/c_cpp_properties.json || cp .vscode/c_cpp_properties.json.orig .vscode/c_cpp_properties.json
	brew tap messense/macos-cross-toolchains
	brew install $(shell lima uname -m)-unknown-linux-gnu
	test -d linux || git clone --depth=1 --branch v6.2 https://github.com/torvalds/linux.git
	cd linux && lima make tinyconfig
	cd linux && lima make -j
