#!/bin/bash

cat << EOF > /dev/wasm3
{
    "command": "load",
    "module": "dns",
    "code": "$(base64 -w0 samples/target/wasm32-unknown-unknown/release/webassembly.wasm)"
}
EOF
