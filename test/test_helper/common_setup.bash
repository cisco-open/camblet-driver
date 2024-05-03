#!/usr/bin/env bash

_common_setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'

    PROJECT_ROOT="$( cd "$( dirname "$BATS_TEST_FILENAME" )/.." >/dev/null 2>&1 && pwd )"
    PATH="$PROJECT_ROOT/src:$PATH"
}

# Run the kernel module with kTLS
_run_kernel_modul_with_ktls() {
    sudo modprobe tls
    sudo modprobe camblet dyndbg==_ ktls_available=1
    sudo dmesg -T
}

# Run the kernel module without kTLS
_run_kernel_modul_without_ktls() {
    sudo rmmod tls
    sudo modprobe camblet dyndbg==_ ktls_available=0
    sudo dmesg -T
}

_run_file_server() {
    ./file-server >/tmp/file-server.log 2>&1 &
}

_run_file_server_with_TLS() {
    ./file-server -tls -port 8007 >/tmp/file-server-tls.log 2>&1 &
}

_run_file_server_with_TLS_for_passtrhough() {
    ./file-server -tls -port 8010 >/tmp/file-server-tls-passthrough.log 2>&1 &
}

_run_nginx_in_docker() {
    sudo docker run -d --rm -p 8080:80 nginx
}