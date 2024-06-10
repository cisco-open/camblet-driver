import socket
import ssl
import camblet
import ctypes
import http.client as http

hostname = 'localhost'
port = 8010

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Only available in Python 3.12+
TCP_ULP = 31

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

    #print(sock.setsockopt(socket.SOL_TCP, TCP_ULP, camblet.CAMBLET))
    sock.connect((hostname, port))

    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())

        tls_info_data = ssock.getsockopt(camblet.SOL_CAMBLET, camblet.CAMBLET_TLS_INFO, ctypes.sizeof(camblet.CambletTlsInfo))
        tls_info = camblet.CambletTlsInfo.from_buffer_copy(tls_info_data)
        print(f"""Camblet TLS Info
Camblet: {tls_info.camblet_enabled}
ALPN: {tls_info.alpn}
SPIFFE ID: {tls_info.spiffe_id}
Peer SPIFFE ID: {tls_info.peer_spiffe_id}\n""")

        assert tls_info.alpn == b'camblet/passthrough'

        # send some data
        request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % hostname
        ssock.send(request.encode())

        response = http.HTTPResponse(ssock)
        response.begin()
        print(response.status)
        print(response.headers)
        print(response.read().decode())
        response.close()
