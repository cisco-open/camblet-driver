#!/usr/bin/env bash

# Teardown the kernel module
_teardown_kernel_modul() {
    echo "teardown kernel modul"
    # sudo dmesg -T
    sudo rmmod camblet
    sudo rmmod bearssl
}

_teardown_camblet_agent() {
    # cat /tmp/camblet-agent.log
    sudo pkill camblet
}

_teardown_file_server() {
    # cat /tmp/file-server.log
    sudo pkill file-server
}

_teardown_python_apps() {
    # cat /tmp/python.log
    sudo pkill python3
}

_teardown_docker_containers() {
    sudo docker rm -f $(sudo docker ps -a -q)
}