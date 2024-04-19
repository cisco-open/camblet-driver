import ctypes

SOL_CAMBLET = 7891
CAMBLET_HOSTNAME = 1
CAMBLET_TLS_INFO = 2
CAMBLET = b"camblet\0"

CAMBLET_EINVALIDSPIFFEID = 1001

class CambletTlsInfo(ctypes.Structure):
    _fields_ = [('camblet_enabled', ctypes.c_bool),
                ('mtls_enabled', ctypes.c_bool),
                ('spiffe_id', ctypes.c_char * 256),
                ('peer_spiffe_id', ctypes.c_char * 256),
                ('alpn', ctypes.c_char * 256)]
