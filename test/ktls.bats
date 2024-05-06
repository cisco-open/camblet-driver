# Runs only once before every test
setup_file() {
    load 'test_helper/common_setup'
    load 'test_helper/common_teardown'

    _common_setup
    _run_kernel_modul_with_ktls
    _run_agent
    _run_file_server
    _run_file_server_with_TLS
    _run_file_server_with_TLS_for_passtrhough
    _run_python_server
    _run_nginx_in_docker
}
# Runs before every test
setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
}
@test "Test a normal directory listing with wget" {
    run wget -d http://localhost:8000/ -O /dev/null
    assert_success
}

@test "Test downloading and uploading 2MB file with curl" {
    run head -c 2M </dev/urandom > bigfile.o
    assert_success
    run curl -v -o /tmp/bigfile_downloaded.o http://localhost:8000/bigfile.o
    assert_success
    run curl -v -F "bigfile_downloaded.o=@/tmp/bigfile_downloaded.o" http://localhost:8000/upload
    assert_success
    run diff bigfile.o bigfile_downloaded.o
    assert_success
}

@test "Test bearSSL with non-bearSSL compatibility" {
    echo "testing with curl using default cipher..."
    run curl -k -v https://localhost:7000/
    assert_success
    echo "testing with curl using AES_GCM_128 cipher..."
    run curl -k -v --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://localhost:7000/
    assert_success
    echo "testing with curl using AES_GCM_256 cipher..."
    run curl -k -v --ciphers ECDHE-RSA-AES256-GCM-SHA384 https://localhost:7000/
    assert_success
    echo "testing with curl using CHACHA_POLY cipher..."
    run curl -k -v --ciphers ECDHE-RSA-CHACHA20-POLY1305 https://localhost:7000/
    assert_success
    echo "testing with wget..."
    run wget --no-check-certificate https://localhost:7000/ -O/dev/null
    assert_success
}

@test "Test openssl client connect to python with various ciphers" {
    run bash -c "echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -connect 127.0.0.1:7000"
    assert_success
    echo "Test openssl client connect to python with ECDHE-RSA-CHACHA20-POLY1305 cipher"
    run bash -c echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -cipher ECDHE-RSA-CHACHA20-POLY1305 -connect 127.0.0.1:7000
    assert_success
}

@test "Test file-server under load using curl" {
    echo "response" > testfile
    echo -e "    100 0\n    100 response" > test.output
    run bash -c 'for i in `seq 1 100`; do curl -s localhost:8000/testfile; echo $?; done |sort|uniq -c|diff - test.output'
    assert_success
}

@test "Test sendfile with NGiNX under load using curl" {
    echo -e "    100 0" > test.output
    run bash -c 'for i in `seq 1 100`; do curl -s -o/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output'
    assert_success
}

@test "Test sendfile with NGiNX under load using wget" {
    echo -e "    100 0" > test.output
    run bash -c 'for i in `seq 1 100`; do wget -q -O/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output'
    assert_success
}

@test "Test sockopt on file-server with TLS" {
    run ./sockopt
    assert_success
}

@test "Test passthrough ALPN on file-server with TLS" {
    run python3 test/passthrough.py
    assert_success
}

@test "Test various recv flag parameters" {
    run ./flags
    assert_success
}

# Runs after every test
teardown() {
    rm -f testfile test.output   
}
# Runs only once after every test
teardown_file() {
    _teardown_file_server
    _teardown_python_apps
    _teardown_docker_containers
    _teardown_kernel_modul
    _teardown_camblet_agent
}