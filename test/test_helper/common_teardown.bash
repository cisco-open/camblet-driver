#!/usr/bin/env bash

# Teardown the kernel module
_teardown_kernel_modul() {
    sudo rmmod camblet
    sudo rmmod bearssl
}

_teardown_camblet_agent() {
    sudo pkill camblet
}

_teardown_file_server() {
    sudo pkill file-server
}

_teardown_python_apps() {
    sudo pkill python3
}

_teardown_docker_containers() {
    sudo docker rm -f $(sudo docker ps -a -q)
}