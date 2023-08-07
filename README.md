# wasm-kernel-module

[![Makefile CI](https://github.com/cisco-open/wasm-kernel-module/actions/workflows/build.yml/badge.svg)](https://github.com/cisco-open/wasm-kernel-module/actions/workflows/build.yml)

This Linux Kernel module runs and exposes a [Wasm](https://webassembly.org) runtime as a proof of concept for checking:
- Wasm is capable of running the kernel space
- running code in kernel space in almost all languages compiled to Wasm
- expose Wasm functionality written in Wasm to eBPF securely
- run [proxy-wasm](https://github.com/proxy-wasm/spec) filters on TCP sockets

## Why doing this?

[eBPF](https://ebpf.io) is a fine piece of technology for doing low-level tracing, traffic shifting, authorization, and other cool things in the kernel space, and a user space counterpart of an eBPF program helps it to manage more complex logic. Wasm is a fine piece of technology to write more [complex business logic](https://www.secondstate.io/articles/ebpf-and-webassembly-whose-vm-reigns-supreme/) (it is Turing-complete). This project aims to create such a setup, where one can support an eBPF program next from Kernel space, with user space level logic, written in Wasm, exposed as a normal Kernel function, instead of communicating through eBPF maps to user space.

### Presentations

This project was presented on KubeCon 2023 Amsterdam, Wasm Day, you can find the recording [here](https://www.youtube.com/watch?v=JSKNch6piyY).

## Which Wasm runtime?

The [wasm3](https://github.com/wasm3/wasm3) runtime got chosen since it is written in C and has minimal dependencies (except a C library) and it is extremely portable. In kernel space, there is no libc, but we maintain a fork of wasm3 which can run in kernel space as well (check the `third-party/wasm3/` submodule).

Current restrictions for kernel-space wasm3:
- no floating point support [can be soft-emulated if needed]
- no WASI support

## Development environment

Checkout the code before you start:

```bash
git clone --recurse-submodules https://github.com/cisco-open/wasm-kernel-module.git
cd wasm-kernel-module
```

### Lima

Our primary development environment is [Lima](https://lima-vm.io) since it supports x86_64 and ARM as well. The module was tested on Ubuntu and Arch Linux and requires kernel version 5.19 and upwards.

Install Lima itself, for example on macOS using brew:
```bash
brew install lima
```

Launch the default VM which is an Ubuntu and matches the host's architecture by default:
```bash
limactl start

# You may also start the VM with your user home mounted as writable with this one-liner:
limactl start --set '.mounts[0].writable=true' --tty=false
```

Setup the required dependencies in the VM:

```bash
lima # enter the VM
sudo apt update && sudo apt install make
make setup-vm
```

### Vagrant/Virtualbox

If you happen to use Vagrant, there is a Vagrantfile prepared which uses VirtualBox.

On macOS install Vagrant and VirtualBox with brew:

```bash
brew install vagrant virtualbox
```

Bring up the Vagrant machine, this installs the required dependencies automatically into it:

```bash
vagrant up
```

Connect to the Vagrant machine through SSH:

```bash
vagrant ssh
```

### Coding

We are using VSCode for development and the project ships with a `c_cpp_properties.json` file which contains the required include paths for the kernel headers. The file is ARM specific from include path point-of-view so if you happen to run on x86_64 please replace the paths accordingly (arm64 -> x86, aarch64 -> x86_64).

You will also need a Linux source bundle, to have full navigation in the source code. The easiest way is to run the `setup-dev-env` target after you already have created a working and configured VM in Lima (with `lima make setup-vm`). This target installs the necessary GCC cross-compilers for IntelliSense, clones the Linux repo, and configures the VSCode workspace accordingly:

```bash
# Start the VM if you haven't already
limactl start

# Setup the development environment
make setup-dev-env
```

## Build and install

*This assumes that you have created a development environment according to the previous section.*

Build the kernel modules(BearSSL and WASM):

```bash
# Enter the VM
lima

# Build on all CPU cores parallelly
make -j$(nproc)
```

Load the kernel modules(BearSSL and WASM):

```bash
make insmod
```

Unload the kernel modules(BearSSL and WASM):

```bash
make rmmod
```

Follow the kernel logs:

```bash
make logs
```

Install the [CLI](https://github.com/cisco-open/wasm-kernel-module-cli) for the kernel module:

```bash
# You can build the module on your workstation
git clone https://github.com/cisco-open/wasm-kernel-module-cli.git
cd wasm-kernel-module-cli
make build-cli

# But you need to run it in the VM, where the device is exposed
lima sudo ./w3k server
```

Then follow the instructions [here](https://github.com/cisco-open/wasm-kernel-module-cli#cli).


## TLS Certificates for testing

You will need `cfssl` for this (`brew install cfssl` on macOS):

```bash
# Create the CA certificate
cfssl gencert -initca ca.json | cfssljson -bare ca

# Create the client/server certificate
cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=server.json \
  -profile=server \
  server.json | cfssljson -bare server
```


Generate the static C resources of these certificates with BearSSL's `brssl` CLI and copy these into the given [certificate_rsa.h](certificate_rsa.h) header file:

```bash
# Trust anchor (CA)
brssl ta ca.pem

# Server certificate
brssl chain server.pem

# Server private key
brssl skey -C server-key.pem
```

## Test mTLS

The kernel module offers TLS termination on certain ports selected by a rule-set:

```bash
# Build and insert the module, then follow the logs
make
make insmod
make logs

# In another terminal start a server
lima python3 -m http.server

# In another terminal connect to the server (over plaintext, will be TLS terminated by the kernel)
lima curl -v http://localhost:8000
```

## DKMS Support

Linux kernel modules need to be built against a specified kernel version, this is when dynamic kernel module support, [DKMS](https://github.com/dell/dkms) comes in handy. The DKMS framework enables you to automatically re-build kernel modules into the current kernel tree as you upgrade your kernel.

The Wasm kernel module has support for DKMS, you can use it in the following way currently:

```bash
sudo git clone --recurse-submodule --branch dkms https://github.com/cisco-open/wasm-kernel-module.git /usr/src/wasm-0.1.0/

# Add the kernel module to the DKMS source control
sudo dkms add -m wasm -v 0.1.0

# Build and install the kernel module against the current kernel version
sudo dkms install -m wasm -v 0.1.0

# Check the logs that the module got loaded
sudo dmesg -T
```

Un-installation is very simple as well:

```bash
sudo dkms uninstall -m wasm -v 0.1.0
sudo dkms remove -m wasm -v 0.1.0
```
