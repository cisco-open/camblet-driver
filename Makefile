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
ifeq ($(ARCH), armv7l)
	ccflags-remove-y += -msoft-float
	ccflags-y += -mhard-float
	# ccflags-y += -mfloat-abi=softfp
endif

KBUILD_EXTRA_SYMBOLS = $(PWD)/third-party/BearSSL/Module.symvers
EXTRA_CFLAGS = -Wall -g

ccflags-remove-y += -Wdeclaration-after-statement

VERBOSE := 1

# obj-m specifies we're a kernel module.
obj-m += nasp.o
nasp-objs :=  third-party/wasm3/source/m3_api_libc.o \
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
			  buffer.o \
			  device_driver.o \
			  main.o \
			  csr.o \
			  rsa_tools.o \
			  cert_tools.o \
			  wasm.o \
			  opa.o \
			  proxywasm.o \
			  socket.o \
			  task_context.o \
			  tls.o \
			  commands.o \
			  string.o \
			  augmentation.o \
			  config.o \
			  sd.o

# Set the path to the Kernel build utils.
KBUILD=/lib/modules/$(shell uname -r)/build/

default: bearssl
	$(MAKE) -C $(KBUILD) M=$(PWD) V=$(VERBOSE) modules

bearssl:
	cd third-party/BearSSL && $(MAKE) linux-km

static/socket_wasm.h: socket.rego
	opa build -t wasm -e "socket/allow" socket.rego -o bundle.tar.gz
	tar zxf bundle.tar.gz /policy.wasm
	mv policy.wasm socket.wasm
	xxd -i socket.wasm static/socket_wasm.h

static/csr_wasm.h: wasm-modules/csr-rust/**/*.rs
	cargo build --release --target=wasm32-unknown-unknown
	cp target/wasm32-unknown-unknown/release/csr-rust.wasm csr.wasm
	xxd -i csr.wasm static/csr_wasm.h

opa-test:
	opa test *.rego -v

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
	rm -rf target/

help:
	$(MAKE) -C $(KBUILD) M=$(PWD) help

logs:
	sudo dmesg -T --follow

insmod-tls:
	@find /lib/modules/$(uname -r) -type f -name '*.ko*' | grep -w tls > /dev/null && sudo modprobe tls || echo "tls module not available"
	
insmod-bearssl: insmod-tls
	sudo insmod third-party/BearSSL/bearssl.ko

insmod: insmod-bearssl
	$(eval ktls_available := $(shell lsmod | grep -w tls > /dev/null && echo 1 || echo 0))
	sudo insmod nasp.ko dyndbg==_ ktls_available=$(ktls_available)

insmod-with-proxywasm: insmod-bearssl
	sudo insmod nasp.ko proxywasm_modules=1

rmmod:
	sudo rmmod nasp
	sudo rmmod bearssl

_debian_deps:
	sudo apt update
	sudo apt install -y dkms dwarves
ifndef GITHUB_ACTION
	sudo apt install -y golang flex bison iperf socat debhelper
endif

_archlinux_deps:
	sudo pacman -Syu linux-headers dkms go strace bc iperf socat

_rhel_deps:
	sudo dnf install -y --enablerepo epel dkms vim-common go

_install_opa:
	sudo curl -L -o /usr/bin/opa https://openpolicyagent.org/downloads/v0.56.0/opa_linux_$(shell go version | cut -f2 -d'/')_static
	sudo chmod +x /usr/bin/opa

_install_wasm_target:
ifndef GITHUB_ACTION
	sudo curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	sudo ln -s $$HOME/.cargo/bin/* /usr/bin/
	rustup default stable
	rustup target add wasm32-unknown-unknown
	sudo rustup default stable
	sudo rustup target add wasm32-unknown-unknown
endif

setup-vm: _debian_deps _install_opa _install_wasm_target

setup-archlinux-vm: _archlinux_deps _install_opa _install_wasm_target

setup-dev-env:
	test -f .vscode/c_cpp_properties.json || cp .vscode/c_cpp_properties.json.orig .vscode/c_cpp_properties.json
	brew tap messense/macos-cross-toolchains
	brew install $(shell lima uname -m)-unknown-linux-gnu
	test -d ../linux || git clone --depth=1 --branch v6.2 https://github.com/torvalds/linux.git ../linux
	cd ../linux && lima make tinyconfig
	cd ../linux && lima make -j

# Usage: make debug LINE=get_command+0x88/0x130
debug:
	sudo addr2line -e nasp.ko $(LINE)

deb:
	$(eval PACKAGE_VERSION := $(shell dpkg-parsechangelog -S Version | cut -d'-' -f1))
	make clean
	rm -f ../nasp-kernel-module_$(PACKAGE_VERSION).orig.tar.xz
	tar --exclude='./.git' --exclude='linux' -cvJf ../nasp-kernel-module_$(PACKAGE_VERSION).orig.tar.xz .
	dpkg-buildpackage -tc
