# camblet-driver

[![Makefile CI](https://github.com/cisco-open/camblet-driver/actions/workflows/build.yml/badge.svg)](https://github.com/cisco-open/camblet-driver/actions/workflows/build.yml)

## Introduction

The *camblet-driver* is the supporting Linux kernel module for the [Camblet](https://github.com/cisco-open/camblet) system. It is capable of enhancing plain old TCP sockets in a frictionless way so that application developers can focus on their business logic instead of dealing with the complexity of TLS, mTLS, and other security-related concerns. It is doing this seamlessly, no code changes or re-compilations or re-deployments are required.

The features are the following:

- providing zero-trust identity for UNIX TCP sockets through mTLS
- access control, authorization and authentication (through OPA)
- providing frictionless TLS termination for those TCP sockets
- supporting every Linux-based machine (bare-metal, vanilla VM, Kubernetes, etc... you name it)

### Presentations

The early incarnation of this project was presented on KubeCon 2023 Amsterdam, Wasm Day, you can find the recording [here](https://www.youtube.com/watch?v=JSKNch6piyY). By that time the module was capable of running OPA -> Wasm compiled policies in the Kernel and those were exposed as an eBPF function from the kernel module.

## Which Wasm runtime?

The [wasm3](https://github.com/wasm3/wasm3) runtime was chosen since it is written in C and has minimal dependencies (except a C library) and it is extremely portable. In kernel space, there is no libc, but we maintain a fork of wasm3 which can run in kernel space as well (check the `third-party/wasm3/` submodule).

Current restrictions for kernel-space wasm3:

- no floating point support [can be soft-emulated if needed]
- no WASI support

## Development environment

Checkout the code before you start:

```bash
git clone --recurse-submodules https://github.com/cisco-open/camblet-driver.git
cd camblet-driver
```

### Lima

Our primary development environment is [Lima](https://lima-vm.io) since it supports x86_64 and ARM as well. The module was tested on Ubuntu and Arch Linux and requires kernel version 5.15 and upwards.

Install Lima itself, for example on macOS using `brew`:

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

### Coding

We are using VSCode for development and the project ships with a `c_cpp_properties.json` file which contains the required paths for the kernel headers. The file is ARM specific from include path point-of-view so if you happen to run on x86_64 please replace the paths accordingly (arm64 -> x86, aarch64 -> x86_64).

We are respecting your `c_cpp_properties.json` file by not overriding it. Please copy the required parts to your file, if it is already present.

You will also need a Linux source bundle, to have full navigation in the source code. The easiest way is to run the `setup-dev-env` target after you already have created a working and configured VM in Lima (with `lima make setup-vm`). This target installs the necessary GCC cross-compilers for IntelliSense, clones the Linux repo, and configures the VSCode workspace accordingly:

```bash
# Start the VM if you haven't already
limactl start

# Setup the development environment
make setup-dev-env
```

## Build and run

*This assumes that you have created a development environment according to the previous section.*

Build the kernel modules(BearSSL and Camblet):

```bash
# Enter the VM
lima

# Build on all CPU cores parallelly
make -j$(nproc)
```

Load the kernel modules(BearSSL and Camblet):

```bash
make insmod
```

Unload the kernel modules(BearSSL and Camblet):

```bash
make rmmod
```

Follow the kernel logs:

```bash
make logs
```

Install the [CLI](https://github.com/cisco-open/camblet) for the kernel module:

```bash
# You can build the module on your workstation
git clone https://github.com/cisco-open/camblet.git
cd camblet
GOOS=linux make build

# But you need to run it in the VM, where the device is exposed
lima sudo build/camblet agent --policies-path $(pwd)/camblet.d/policies --services-path $(pwd)/camblet.d/services
```

Then follow the instructions [here](https://github.com/cisco-open/camblet#cli).

## TLS Termination

The kernel module can terminate TLS connections for ordinary TCP sockets (IPv4 or IPv6), and forward the plaintext traffic to a user space application.

Between two applications - both of them intercepted by this module - the traffic is always encrypted by [kTLS](https://docs.kernel.org/networking/tls-offload.html). If one of them is not intercepted by the module but supports the ChaCha20-Poly1305 AEAD - kTLS is used. Otherwise, the traffic is encrypted by BearSSL.

## Debugging

Most of the logs of this module are on debug level and can be shown using [dynamic debug](https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html) feature of the Linux kernel.

Use the following command to turn on debug level logging for the module:

```bash
echo -n '-p; module camblet file opa.c  +pftl' | sudo tee /proc/dynamic_debug/control > /dev/null
```

### Test mTLS

The kernel module offers TLS termination on certain ports selected by an [OPA](https://www.openpolicyagent.org) rule-set:

```bash
# Edit the rule-set
vim socket.rego

# Build and insert the module, then follow the logs
make
make insmod
make logs

# In another terminal start a server
lima python3 -m http.server --protocol HTTP/1.1

# In another terminal connect to the server (over plaintext, will be TLS terminated by the kernel)
lima curl -v http://localhost:8000
```

## Installation

It is also possible to manually install the kernel module with [DKMS](https://github.com/dell/dkms).

### DKMS Support

Linux kernel modules need to be built against a specified kernel version, this is when dynamic kernel module support, [DKMS](https://github.com/dell/dkms) comes in handy. The DKMS framework enables you to automatically re-build kernel modules into the current kernel tree as you upgrade your kernel, so you don't need to re-build them manually every time.

#### Install DKMS

Ensure that DKMS is installed on your system. You can typically install it using your distribution's package manager.

For example, on Debian-based systems:

```bash
sudo apt install dkms
```

On Red Hat compatible systems:

```bash
sudo dnf install --enablerepo epel dkms
```

On Amazon Linux:

```bash
sudo dnf install dkms
```

#### Prepare the Camblet kernel module

The Camblet can be installed with DKMS in the following way currently:

```bash
sudo git clone --recurse-submodule https://github.com/cisco-open/camblet-driver.git /usr/src/camblet-0.6.0/

# Add the kernel module to the DKMS source control
sudo dkms add -m camblet -v 0.6.0

# Build and install the kernel module against the current kernel version
sudo dkms install -m camblet -v 0.6.0

# Load the kernel module
sudo modprobe camblet

# Check the logs that the module got loaded
sudo dmesg -T
```

Un-installation is very simple as well:

```bash
# Unload the kernel module
sudo modprobe -r camblet

# Remove the kernel module from DKMS source control
sudo dkms uninstall -m camblet -v 0.6.0
sudo dkms remove -m camblet -v 0.6.0
```

### Debian package

The kernel module can be packaged into a Debian package with DKMS support, so kernel module re-builds are handled automatically.

#### Building the package for yourself

Prepare the build environment, if you want to build the package on your workstation:

```bash
sudo apt install debhelper
```

The package can be built with the following command:

```bash
make deb
```

The package can be installed with the following command:

```bash
sudo apt install ../camblet-driver_0.4.0-1_all.deb
```

### RPM package

The kernel module can be packaged into an RPM package with DKMS support, so kernel module re-builds are handled automatically.

#### Building the package for yourself

Prepare the build environment, if you want to build the package on your workstation:

```bash
sudo dnf install rpm-build
```

The package can be built with the following command:

```bash
make rpm
```

The package can be installed with the following command:

```bash
sudo dnf install ../camblet-driver-0.4.0-1.noarch.rpm
```
