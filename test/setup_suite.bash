#!/usr/bin/env bash
setup_suite() {
    _install_setup_prerequisits
    _build_and_install_camblet_with_dkms
    _build_and_install_camblet_cli
    _build_go_file_server
    _build_sockopt
    _build_flags
}

_install_setup_prerequisits() {
    make setup-vm
    sudo apt install openssl docker.io -y
}

_build_and_install_camblet_with_dkms() {
    TEST_TAG=0.0.0
    sudo cp -r . /usr/src/camblet-$TEST_TAG/
    sudo dkms add -m camblet -v $TEST_TAG
    if sudo dkms build -m camblet -v $TEST_TAG; then
        echo "DKMS build succeeded"
    else
        echo "DKMS build failed"
        cat /var/lib/dkms/camblet/$TEST_TAG/build/make.log
        exit 1
    fi
    sudo dkms install -m camblet -v $TEST_TAG
}

_build_and_install_camblet_cli() {
    if [[ "${GITHUB_ACTION}" ]]; then
        echo "checking out '${GITHUB_HEAD_REF:-${GITHUB_REF#refs/heads/}}' branch"
        git checkout ${GITHUB_HEAD_REF:-${GITHUB_REF#refs/heads/}} || echo "branch not found"
    fi
    cd ../camblet
    make build
    sudo mkdir -p /etc/camblet
    sudo cp -a camblet.d/policies /etc/camblet/
    sudo cp -a camblet.d/services /etc/camblet/
    sudo cp config.yaml /etc/camblet/config.yaml
    sudo cp build/camblet /usr/local/bin/
    cd ../camblet-driver
}

_build_go_file_server() {
    echo "building go file server"
    go build test/file-server.go
}

_build_sockopt() {
    gcc -o sockopt test/sockopt.c
}

_build_flags() {
    gcc -o flags test/recvflags.c
}


teardown_suite() {
    echo "Teardown suite started...."
    _teardown_file_server
    _teardown_flags
    _teardown_sockopt
    sudo dkms remove camblet/$TEST_TAG
    sudo rm -rf /usr/src/camblet-$TEST_TAG/
}

_teardown_file_server() {
    rm file-server
}

_teardown_sockopt() {
    rm sockopt
}

_teardown_flags() {
    rm flags
}