#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <memory>
#include <cmath>
#include <cstdio>
#include <cstring>
#include "crypto.hpp"
#include "exception.hpp"

void initialize_crypto()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void crypto_cleanup()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

std::shared_ptr<EVP_PKEY> generate_rsa_keypair(int bits)
{
    double log = log10(bits)/log10(2);
    if((int)log - log != 0)
    {
        throw rsa_generation_exception("RSA bits must be a power of two!");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx)
    {
        throw rsa_generation_exception("Unable to create RSA key generation context!");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw rsa_generation_exception("Unable to initialize the RSA key generation!");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw rsa_generation_exception("Unable to set RSA key padding!");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw rsa_generation_exception("Unable to set RSA generation bits!");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw rsa_generation_exception("Unable to generate RSA key!");
    }

    EVP_PKEY_CTX_free(ctx);
    return std::shared_ptr<EVP_PKEY>(pkey, EVP_PKEY_free);
}

std::string bio_to_pem_string(BIO* bio)
{
    char* buffer;

    int size = (int) BIO_get_mem_data(bio, &buffer);
    if(size < 0)
    {
        throw pem_conversion_exception("Failed to get BIO memory data!");
    }

    std::string ret(buffer);

    return ret;
}

std::string get_x509_data(std::shared_ptr<X509> x509)
{
    BIO* bio = BIO_new(BIO_s_mem());
    if(bio == nullptr)
    {
        throw pem_conversion_exception("Failed to create BIO object!");
    }

    if(PEM_write_bio_X509(bio, x509.get()) == 0)
    {
        throw pem_conversion_exception("Failed to write public PEM data to BIO!");
    }

    std::string x509_data = bio_to_pem_string(bio);

    BIO_free(bio);

    return x509_data;
}

std::shared_ptr<rsa_keypair_t> get_keypair_data(std::shared_ptr<EVP_PKEY> pkey)
{
    std::shared_ptr<rsa_keypair_t> data = std::make_shared<rsa_keypair_t>();

    // Extract public key
    BIO* bio = BIO_new(BIO_s_mem());
    if(bio == nullptr)
    {
        throw pem_conversion_exception("Failed to create BIO object!");
    }

    if(PEM_write_bio_PUBKEY(bio, pkey.get()) == 0)
    {
        throw pem_conversion_exception("Failed to write public PEM data to BIO!");
    }

    data->public_key = bio_to_pem_string(bio);

    BIO_free(bio);

    // Extract private key
    bio = BIO_new(BIO_s_mem());
    if(bio == nullptr)
    {
        throw pem_conversion_exception("Failed to create BIO object!");
    }

    if(PEM_write_bio_PKCS8PrivateKey(bio, pkey.get(), NULL, NULL, 0, 0, NULL) == 0)
    {
        throw pem_conversion_exception("Failed to write private PEM data to BIO!");
    }

    if(EVP_PKEY_print_private(bio, pkey.get(), NULL, NULL) < 1)
    {
        throw pem_conversion_exception("Failed to print private key!");
    }

    data->private_key = bio_to_pem_string(bio);

    BIO_free(bio);

    return data;
}

int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

std::shared_ptr<X509> generate_user_cert(std::shared_ptr<EVP_PKEY> pkey, const char* username)
{
    std::shared_ptr<X509> x509(X509_new(), X509_free);
    if(x509.get() == nullptr)
    {
        throw cert_generation_exception("Failed to allocate a new X509 certificate!");
    }

    X509_set_version(x509.get(),2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()),1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()),0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()),(long)60*60*24*365);

    if(X509_set_pubkey(x509.get(), pkey.get()) == 0)
    {
        throw cert_generation_exception("Failed to set the X509 public key!");
    }

    X509_NAME* name = X509_get_subject_name(x509.get());
    if(name == nullptr)
    {
        throw cert_generation_exception("Failed to get the X509 subject name!");
    }

    if(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"OpenVPN Access", -1, -1, 0) == 0)
    {
        throw cert_generation_exception("Failed to set X509 organization!");
    }

    if(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)username, -1, -1, 0) == 0)
    {
        throw cert_generation_exception("Failed to set X509 CN!");
    }

    if(X509_set_issuer_name(x509.get(), name) == 0)
    {
        throw cert_generation_exception("Failed to set X509 subject name!");
    }

    /* Add various extensions: standard extensions */
    add_ext(x509.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_ext(x509.get(), NID_key_usage, "critical,keyCertSign,cRLSign");

    add_ext(x509.get(), NID_subject_key_identifier, "hash");

    /* Some Netscape specific extensions */
    add_ext(x509.get(), NID_netscape_cert_type, "sslCA");

    return x509;
}

void sign_user_x509(std::shared_ptr<X509> x509, std::shared_ptr<EVP_PKEY> ca_key)
{
    if(X509_sign(x509.get(), ca_key.get(), EVP_sha256()) == 0)
    {
        throw failed_signing_exception("Failed to sign user x509!");
    }
}

std::shared_ptr<EVP_PKEY> load_private_key_file(const char* path)
{
    FILE* private_key_file = fopen(path, "r");
    if(private_key_file == nullptr)
    {
        throw file_not_found_exception(path);
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if(PEM_read_PrivateKey(private_key_file, &pkey, NULL, NULL) == 0)
    {
        throw pem_load_exception("Failed to read PEM key from file!");
    }

    return std::shared_ptr<EVP_PKEY>(pkey, EVP_PKEY_free);;
}
