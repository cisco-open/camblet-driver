ktls_in_use=false;

load 'test_helper/bats-support/load.bash'
load 'test_helper/bats-assert/load.bash'
load 'test_helper/common.bash'

@test "Test if the non-ktls enabled kernel modul is in use" {
    run cat /sys/module/camblet/parameters/ktls_available
    assert_output 'N'
}

@test "Test a normal directory listing with wget on IPv4" {
    wget -4 -d http://localhost:8000/ -O /dev/null
}

@test "Test a normal directory listing with wget on IPv6" {
    wget -6 -d http://localhost:8000/ -O /dev/null
}

@test "Test downloading and uploading 2MB file with curl" {
    head -c 2M </dev/urandom > bigfile.o
    curl -v -o /tmp/bigfile_downloaded.o http://localhost:8000/bigfile.o
    curl -v -F "bigfile_downloaded.o=@/tmp/bigfile_downloaded.o" http://localhost:8000/upload
    diff bigfile.o bigfile_downloaded.o
}

@test "Test bearSSL with non-bearSSL compatibility" {
    echo "testing with curl using default cipher..."
    curl -k -v https://localhost:7000/
    echo "testing with curl using AES_GCM_128 cipher..."
    curl -k -v --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://localhost:7000/
    echo "testing with curl using AES_GCM_256 cipher..."
    curl -k -v --ciphers ECDHE-RSA-AES256-GCM-SHA384 https://localhost:7000/
    echo "testing with curl using CHACHA_POLY cipher..."
    curl -k -v --ciphers ECDHE-RSA-CHACHA20-POLY1305 https://localhost:7000/
    echo "testing with wget..."
    wget --no-check-certificate https://localhost:7000/ -O/dev/null
}

@test "Test openssl client connect to python with various ciphers" {
    echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -connect 127.0.0.1:7000
    echo "Test openssl client connect to python with ECDHE-RSA-CHACHA20-POLY1305 cipher"
    echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -cipher ECDHE-RSA-CHACHA20-POLY1305 -connect 127.0.0.1:7000
}

@test "Test file-server under load using curl" {
    echo "response" > testfile
    echo -e "    100 0\n    100 response" > test.output
    for i in `seq 1 100`; do curl -s localhost:8000/testfile; echo $?; done |sort|uniq -c|diff - test.output
}

@test "Test sendfile with NGiNX under load using curl" {
    echo -e "    100 0" > test.output
    for i in `seq 1 100`; do curl -s -o/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output
}

@test "Test sendfile with NGiNX under load using wget" {
    echo -e "    100 0" > test.output
    for i in `seq 1 100`; do wget -q -O/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output
}

@test "Test sockopt on file-server with TLS" {
    ./sockopt
}

@test "Test passthrough ALPN on file-server with TLS" {
    python3 test/passthrough.py
}

@test "Test various recv flag parameters" {
    ./flags
}