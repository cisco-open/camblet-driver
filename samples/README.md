# WebAssembly samples in various languages

## Setup Rust

```bash
brew install rustup
rustup-init
rustup target add wasm32-unknown-unknown
```

## Build the examples

```bash
# Rust
cargo build --target wasm32-unknown-unknown --release

# C + Zig
zig build-lib -target wasm32-freestanding main.zig -lc -dynamic
zig build-lib -target wasm32-freestanding main.c -lc -dynamic

# Go
go install github.com/mailru/easyjson/...@latest
easyjson -all -snake_case ./dns/
tinygo build -o dns-go.wasm -target wasm -wasm-abi=generic -gc=leaking main.go
```
