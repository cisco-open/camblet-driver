#include "bearssl.h"

int init_rnd_gen(void);
uint32_t generate_rsa_keys(br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub);
size_t encode_rsa_priv_key_to_der(unsigned char *der, br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub);