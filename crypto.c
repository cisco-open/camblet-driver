#include "crypto.h"

#include <keys/asymmetric-type.h>


struct key *request_rsa_key(const char *description, const char *callout_info)
{
    return request_key(&key_type_asymmetric, description, callout_info);
}

