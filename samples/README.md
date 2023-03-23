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

This directory contains WebAssembly targeted example applications, the main one is a DNS packet capturer/parser application written in Rust, compiled to Wasm, which gets called back by the kernel module through netfilter:

```bash
# Build the WebAssembly module from the code on your local machine
make build-dns-rust-wasm
# Build the CLI
lima make build-cli
# load the wasm module to the kernel module
lima make load-dns-rust-wasm
# exercise DNS a bit to capture some packages
lima dig +ttlunits telex.hu
# check the logs to see the parsed messages
lima make logs
# The DNS Wasm module exposes DNS latency metrics through UNIX socket in JSON format:
sudo socat - UNIX-CONNECT:/run/wasm.socket
```
