#
# The MIT License (MIT)
# Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

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
