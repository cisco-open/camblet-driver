#pragma once

#include <asm/byteorder.h>

struct dns_h {
    unsigned id : 16;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned rd : 1;
    unsigned tc : 1;
    unsigned aa : 1;
    unsigned opcode : 4;
    unsigned qr : 1;
    unsigned rcode : 4;
    unsigned cd : 1;
    unsigned ad : 1;
    unsigned z : 1;
    unsigned ra : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    unsigned qr : 1;
    unsigned opcode : 4;
    unsigned aa : 1;
    unsigned tc : 1;
    unsigned rd : 1;
    unsigned ra : 1;
    unsigned z : 1;
    unsigned ad : 1;
    unsigned cd : 1;
    unsigned rcode : 4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    unsigned qdcount : 16;
    unsigned ancount : 16;
    unsigned nscount : 16;
    unsigned arcount : 16;
};
