# wasm-kernel-module

This Linux Kernel module runs and exposes a [Wasm](https://webassembly.org) runtime as a proof of concept for checking:
- Wasm is capable of running the kernel space
- running code in kernel space in almost all languages compiled to Wasm
- expose Wasm functionality written in Wasm to eBPF securely

## Why doing this?

[eBPF](https://ebpf.io) is a fine piece of technology for doing low-level tracing, traffic shifting, authorization, and other cool things in the kernel space, and a user space counterpart of an eBPF program helps it to manage more complex logic. Wasm is a fine piece of technology to write more [complex business logic](https://www.secondstate.io/articles/ebpf-and-webassembly-whose-vm-reigns-supreme/) (it is Turing-complete). This project aims to create such a setup, where one can support an eBPF program next from Kernel space, with user space level logic, written in Wasm, exposed as a normal Kernel function, instead of communicating through eBPF maps to user space.

### Presentations

This project was presented on KubeCon 2023 Amsterdam, Wasm Day, you can find the recording [here](https://www.youtube.com/watch?v=JSKNch6piyY).

## Which Wasm runtime?

The [wasm3](https://github.com/wasm3/wasm3) runtime got chosen since it is written in C and has minimal dependencies (except a C library) and it is extremely portable. In kernel space, there is no libc, but we maintain a fork of wasm3 which can run in kernel space as well (check the `thrid-party/wasm3/` submodule).

Current restrictions for kernel-space wasm3:
- no floating point support [can be soft-emulated if needed]
- no WASI support

## Development environment

Our primary development environment is [Lima](https://lima-vm.io) since it supports x86_64 and ARM as well. The module was tested on Ubuntu and Arch Linux and requires kernel version 5.19 and upwards.

As a first step checkout the code:

```bash
git clone --recurse-submodules https://github.com/cisco-open/wasm-kernel-module.git
cd wasm-kernel-module
```

### Lima

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
...
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

## Build and install

*This assumes that you have created a development environment according to the previous section.*

Checkout the code:

```bash
git clone --recurse-submodules git@github.com:cisco-open/wasm-kernel-module.git
cd wasm-kernel-module
```

Build the kernel modules(BearSSL and WASM):

```bash
# Build on all CPU cores parallelly
make -j$(nproc)
```

Load the kernel modules(BearSSL and WASM):
```
make insmod
```

Unload the kernel modules(BearSSL and WASM):
```
make rmmod
```

Follow the kernel logs:
```
make logs
```

Install the [CLI](https://github.com/cisco-open/wasm-kernel-module-cli) for the kernel module:

```bash
git clone https://github.com/cisco-open/wasm-kernel-module-cli.git
cd wasm-kernel-module-cli
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


Generate the static C resources of these certificates with the BearSSL's `brssl` CLI and copy these into the given [certificate_rsa.h](certificate_rsa.h) header file:

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
