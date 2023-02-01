#!/bin/bash
set +ex

# check whether wasm3 module is already loaded
if lsmod |grep "wasm3" >/dev/null; then
    echo "wasm module already loaded";
    chmod 777 /run/wasm.socket
    # load dns wasm module
    cat webassembly.wasm > /dev/wasm
    exit
fi;

# compile wasm3 module
git checkout -f
git submodule update
make

# load wasm3 module
rmmod wasm 2>/dev/null
rm /run/wasm.socket 2>/dev/null
insmod wasm.ko
chmod 777 /run/wasm.socket

# load dns wasm module
cat webassembly.wasm > /dev/wasm
