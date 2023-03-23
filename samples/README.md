# WebAssembly samples in various languages

## Setup Rust

Installing the required language tools (Rust, Go) to compile the sample programs (on macOS):

```bash
brew install rustup tinygo
rustup-init
rustup target add wasm32-unknown-unknown
```

## Build the examples

```bash
# Rust
cargo build --target wasm32-unknown-unknown --release

# Go
go install github.com/mailru/easyjson/...@latest
easyjson -all -snake_case ./dns/
tinygo build -o dns-go.wasm -target wasm -wasm-abi=generic -gc=leaking main.go
```

### DNS Parser module

This directory contains webassembly targeted example applications, the main one is a DNS packet capturer/parser application, which gets called back by the kernel module through netfilter.

```bash
# On your local machine
cd samples/
# build the webassembly module from the code
make rust-sample
# Build the CLI
cd ..
make build-cli
# SSH inside the vagrant machine using vagrant ssh
# and cd into the /vagrant directory
# load the wasm module to the kernel module
make load-dns-rust-wasm
# exercise DNS a bit to capture some packages
dig +ttlunits telex.hu
# check the logs to see the parsed messages
make logs

# use exported metrics through UNIX socket
sudo socat - UNIX-CONNECT:/run/wasm.socket
```
