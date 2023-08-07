#include "rsa_tools.h"

#include "linux/kernel.h"

static br_hmac_drbg_context hmac_drbg_ctx;

// BearSSL RSA Keygen related functions
// Initialize BearSSL random number generator with a unix getrandom backed seeder
void init_rnd_gen()
{

    br_prng_seeder seeder;

    seeder = br_prng_seeder_system(NULL);

    br_hmac_drbg_init(&hmac_drbg_ctx, &br_sha256_vtable, NULL, 0);
    if (!seeder(&hmac_drbg_ctx.vtable))
    {
        printk(KERN_ERR "system source of randomness failed");
    }
}
// BearSSL RSA Keygen related functions
// Generates a 2048 bit long rsa key pair
uint32_t generate_rsa_keys(br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub)
{
    br_rsa_keygen rsa_keygen = br_rsa_keygen_get_default();

    unsigned char raw_priv_key[BR_RSA_KBUF_PRIV_SIZE(2048)];
    unsigned char raw_pub_key[BR_RSA_KBUF_PUB_SIZE(2048)];

    uint32_t result = rsa_keygen(&hmac_drbg_ctx.vtable, rsa_priv, raw_priv_key, rsa_pub, raw_pub_key, 2048, 3);
    return result;
}

// BearSSL RSA Keygen related functions
// Encodes rsa private key to pkcs8 der format and returns it's lenght.
// If the der parameter is set to NULL then it computes only the length
size_t encode_rsa_priv_key_to_der(unsigned char *der, br_rsa_private_key *rsa_priv, br_rsa_public_key *rsa_pub)
{
    br_rsa_compute_privexp rsa_priv_exp_comp = br_rsa_compute_privexp_get_default();
    unsigned char priv_exponent[256];
    size_t priv_exponent_size = rsa_priv_exp_comp(priv_exponent, rsa_priv, 3);
    if (rsa_pub->nlen != priv_exponent_size)
    {
        printk("Error happened during priv_exponent generation");
    }
    size_t len = br_encode_rsa_pkcs8_der(der, rsa_priv, rsa_pub, priv_exponent, priv_exponent_size);
    return len;
}