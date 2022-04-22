#!/bin/bash

set -xeou pipefail

sudo rmmod -f wasm3 || true
make
sudo insmod wasm3.ko
dig +ttlunits index.hu
sudo dmesg -T
