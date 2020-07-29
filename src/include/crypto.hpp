#ifndef CERTIFICATE_SERVER_CRYPTO_HPP
#define CERTIFICATE_SERVER_CRYPTO_HPP

#include <openssl/evp.h>
#include <exception>
#include <string>
#include "error.hpp"

typedef struct {
    std::string private_key;
    std::string public_key;
} rsa_keypair_t;

void initialize_crypto();
void crypto_cleanup();
std::string get_x509_data(std::shared_ptr<X509> x509);
std::shared_ptr<EVP_PKEY> generate_rsa_keypair(int bits);
std::shared_ptr<EVP_PKEY> load_private_key_file(const char* path);
std::shared_ptr<rsa_keypair_t> get_keypair_data(std::shared_ptr<EVP_PKEY> pkey);
void sign_user_x509(std::shared_ptr<X509> x509, std::shared_ptr<EVP_PKEY> ca_key);
std::shared_ptr<X509> generate_user_cert(std::shared_ptr<EVP_PKEY> pkey, const char* username);

#endif //CERTIFICATE_SERVER_CRYPTO_HPP
