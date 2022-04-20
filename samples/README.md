# WebAssembly samples in various languages

```bash
cargo build --target wasm32-unknown-unknown --release
zig build-lib -target wasm32-freestanding main.zig -lc -dynamic
zig build-lib -target wasm32-freestanding main.c -lc -dynamic
```
