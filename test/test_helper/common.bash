#!/usr/bin/env bash

_common_setup() {

    PROJECT_ROOT="$( cd "$( dirname "$BATS_TEST_FILENAME" )/.." >/dev/null 2>&1 && pwd )"
    PATH="$PROJECT_ROOT/src:$PATH"
}

# Runs before every bats file
setup_file() {
    _common_setup
    _run_kernel_modul
    _run_agent
    _run_file_server
    _run_file_server_with_TLS
    _run_file_server_with_TLS_for_passtrhough
    _run_python_server
    _run_nginx_in_docker
}
# Runs before every test
# setup() {
# }


_run_kernel_modul() {
    if $ktls_in_use; then
        echo '# Running tests with ktls' >&3
        sudo modprobe tls
        sudo modprobe camblet dyndbg==_ ktls_available=1
    else
        echo '# Running tests with non-ktls' >&3
        sudo rmmod tls
        sudo modprobe camblet dyndbg==_ ktls_available=0
    fi
}

_run_agent() {
    cd ../camblet
    sudo build/camblet agent --policies-path /etc/camblet/policies/ --services-path /etc/camblet/services/ >/tmp/camblet-agent.log 2>&1 &
    camblet_agent_pid=$!
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

# Runs after every test
teardown() {
    rm -f testfile test.output   
}
# Runs after every bats file
teardown_file() {
    _teardown_file_server
    _teardown_python_apps
    _teardown_docker_containers
    _teardown_camblet_agent
    _teardown_kernel_modul
}

_teardown_kernel_modul() {
    if ps -p "$camblet_agent_pid" > /dev/null; then
        sleep 1
    fi
    sudo dmesg -T
    sudo rmmod camblet
    sudo rmmod bearssl
}

_teardown_camblet_agent() {
    cat /tmp/camblet-agent.log
    sudo pkill camblet
}

_teardown_file_server() {
    cat /tmp/file-server.log
    sudo pkill file-server
}

_teardown_python_apps() {
    cat /tmp/python.log
    sudo pkill python3
}

_teardown_docker_containers() {
    sudo docker rm -f $(sudo docker ps -a -q)
}