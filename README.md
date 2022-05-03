# wasm3-kernel-module
This Linux Kernel module running [wasm3](https://github.com/wasm3/wasm3) is a proof of concept for checking:
- wasm is capapble of running the kernel space
- writing kernel modules in all languages compiled to wasm
- expose eBPF like functionality securely through wasm

## Why wasm3?

wasm3 got choosen since it is written in C and has minimal dependencies (except a C library).
In kernel space there is no libc, but we maintain a fork which can run in kernel-space as well (check the wasm3 submodule).
Current restrictions for kernel-space wasm3:
- no floating point support
- no WASI support

## Build and install

Checkout the code:
```
bash
git clone --recurse-submodules git@wwwin-github.cisco.com:eti/wasm3-kernel-module.git
cd wasm3-kernel-module
```

Build the module:
```bash
make
```

Install the module:
```
sudo insmod wasm3.ko
```

Remove the module:
```
sudo rmmod wasm3
```

Follow logs:
```
sudo dmesg -T --follow
```

## Load a wasm module to the kernel module runtime:

### Simple Hello World

The kernel module exposes a character device, which can be used to interact with the module.

Send a wasm module (non-WASI) to the runtime through the char device:

```wat
(module
  ;; _debug is exported by the wasm3 runtime
  (import "env" "_debug" (func $printf (param i32 i32) (result i32))) 
  (memory $0 1)
  (data (i32.const 0) "Hello")
  (func (export "main") (param i32 i32) (result i32)
      i32.const 0  ;; pass offset 0 to printf
      i32.const 5  ;; pass length 5 to printf
      (call $printf)))
```

```bash
wat2wasm hello.wat
sudo sh -c "cat hello.wasm > /dev/wasm3"
```

Check the kernel logs for the `Hello` message.

### DNS Parser module

The `samples/` directory contains webassembly targeted example applications, the main one is a DNS packet capturer/parser application, which gets called back by the kernel module through netfilter.

```bash
cd samples/
# check/edit the code if you like
vim main.rs
# build the webassembly module from the code
cargo build --target wasm32-unknown-unknown --release
# load the wasm module to the kernel module
sudo sh -c "cat ./target/wasm32-unknown-unknown/release/webassembly.wasm > /dev/wasm3"
# exercise DNS a bit to capture some packages
dig +ttlunits telex.hu
# check the logs to see the parsed messages
sudo dmesg -T --follow


# use exported metrics through UNIX socket
sudo socat - UNIX-CONNECT:/tmp/wasm3
# always delete the socket file before loading the kernel module again
sudo rm -f /tmp/wasm3
```

## Development environment

### Vagrant/Virtualbox

```bash
brew install vagrant virtualbox virtualbox-extension-pack
```

```bash
vagrant up
```

```bash
vagrant ssh
```
