#!/bin/bash

set -euo pipefail

function finish {
    echo "Stop processes"
    sudo pkill python3
    sudo pkill file-server
    sudo docker rm -f $(sudo docker ps -a -q)
}

trap finish EXIT

echo "Building file server"
go build test/file-server.go

echo "Starting file server"
./file-server >/tmp/file-server.log 2>&1 &

echo "Starting file server with TLS"
./file-server -tls -port 8007 >/tmp/file-server-tls.log 2>&1 &

echo "Starting file server with TLS for passthrough"
./file-server -tls -port 8010 >/tmp/file-server-tls-passthrough.log 2>&1 &

echo "Starting NGiNX in docker"
sudo docker run -d --rm -p 8080:80 nginx

sleep 2

echo "Test a normal directory listing with wget"
wget -d http://localhost:8000/ -O /dev/null

echo "Test downloading a bigger file with curl"
head -c 2M </dev/urandom > bigfile.o
curl -v -o /tmp/bigfile_downloaded.o http://localhost:8000/bigfile.o

echo "Test uploading this file"
curl -v -F "bigfile_downloaded.o=@/tmp/bigfile_downloaded.o" http://localhost:8000/upload
diff bigfile.o bigfile_downloaded.o

echo "Test bearssl with non-bearssl compatibility"
python3 -m http.server 7000 >/tmp/python.log &
sleep 1
echo "testing with curl using default cipher..."
curl -k -v https://localhost:7000/
echo "testing with curl using AES_GCM_128 cipher..."
curl -k -v --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://localhost:7000/
echo "testing with curl using AES_GCM_256 cipher..."
curl -k -v --ciphers ECDHE-RSA-AES256-GCM-SHA384 https://localhost:7000/
echo "testing with curl using CHACHA_POLY cipher..."
curl -k -v --ciphers ECDHE-RSA-CHACHA20-POLY1305 https://localhost:7000/
echo "testing with wget..."
wget --no-check-certificate https://localhost:7000/

echo "Test openssl client connect to python with default cipher"
echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -connect 127.0.0.1:7000
echo "Test openssl client connect to python with ECDHE-RSA-CHACHA20-POLY1305 cipher"
echo -e "GET / HTTP/1.1\r\n\r\n" | openssl s_client -cipher ECDHE-RSA-CHACHA20-POLY1305 -connect 127.0.0.1:7000

echo "Test file-server using curl"
rm -f testfile test.output
echo "response" > testfile
echo -e "    100 0\n    100 response" > test.output
for i in `seq 1 100`; do curl -s localhost:8000/testfile; echo $?; done |sort|uniq -c|diff - test.output

echo "Test sendfile with NGiNX using curl"
echo -e "    100 0" > test.output
for i in `seq 1 100`; do curl -s -o/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output

echo "Test sendfile with NGiNX using wget"
echo -e "    100 0" > test.output
for i in `seq 1 100`; do wget -q -O/dev/null localhost:8080; echo $?; done |sort|uniq -c|diff - test.output

echo "Test sockopt on file-server with TLS"
gcc -o sockopt test/sockopt.c
./sockopt

echo "Test passthrough ALPN on file-server with TLS"
python3 test/passthrough.py
