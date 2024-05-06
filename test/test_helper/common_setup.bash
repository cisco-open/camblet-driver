#!/usr/bin/env bash

_common_setup() {
    load 'test_helper/bats-support/load'

    PROJECT_ROOT="$( cd "$( dirname "$BATS_TEST_FILENAME" )/.." >/dev/null 2>&1 && pwd )"
    PATH="$PROJECT_ROOT/src:$PATH"
}

# Run the kernel module with kTLS
_run_kernel_modul_with_ktls() {
    sudo modprobe tls
    sudo modprobe camblet dyndbg==_ ktls_available=1
}

# Run the kernel module without kTLS
_run_kernel_modul_without_ktls() {
    sudo modprobe camblet dyndbg==_ ktls_available=0
}

_run_agent() {
    cd ../camblet
    sudo build/camblet agent --policies-path /etc/camblet/policies/ --services-path /etc/camblet/services/ >/tmp/camblet-agent.log 2>&1 &
    cd ../camblet-driver
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

_run_python_server() {
    python3 -m http.server 7000 >/tmp/python.log &
    sleep 1
}

_run_nginx_in_docker() {
    sudo docker run -d --rm -p 8080:80 nginx
}