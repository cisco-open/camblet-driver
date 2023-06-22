# Generate a private key and a X509 certificate for the CA:

openssl req -new -x509 -nodes -days 365000 \
   -newkey rsa:2048 \
   -keyout ca-key.pem \
   -out ca-cert.pem \
   -subj "/C=HU/ST=BP/O=Cisco/CN=root"

# Generate the private key and certificate request:

openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout server-key.pem \
   -out server-req.pem \
   -subj "/C=HU/ST=BP/O=Cisco/CN=localhost"

# Generate the X509 certificate for the server:

openssl x509 -req -days 365000 -CAcreateserial \
   -in server-req.pem \
   -out server-cert.pem \
   -CA ca-cert.pem \
   -CAkey ca-key.pem

# Generate the private key and certificate request:

openssl req -newkey rsa:2048 -nodes -days 365000 \
   -keyout client-key.pem \
   -out client-req.pem \
   -subj "/C=HU/ST=BP/O=Cisco/CN=localhost"

# Generate the X509 certificate for the client:

openssl x509 -req -days 365000 -set_serial 01 \
   -in client-req.pem \
   -out client-cert.pem \
   -CA ca-cert.pem \
   -CAkey ca-key.pem

# Verify the server certificate:

openssl verify -CAfile ca-cert.pem \
   ca-cert.pem \
   server-cert.pem

# Verify the client certificate:

openssl verify -CAfile ca-cert.pem \
   ca-cert.pem \
   client-cert.pem
