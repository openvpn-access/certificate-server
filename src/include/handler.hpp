#ifndef CERTIFICATE_SERVER_HANDLER_HPP
#define CERTIFICATE_SERVER_HANDLER_HPP

#include <openssl/evp.h>
#include <memory>
#include <pistache/endpoint.h>

class CertServerHandler : public Pistache::Http::Handler {
private:
    const std::string& ta_key;
    const std::string& ca_cert;
    std::shared_ptr<EVP_PKEY> ca_key;

    HTTP_PROTOTYPE(CertServerHandler)

    void onRequest(const Pistache::Http::Request &req, Pistache::Http::ResponseWriter response) override;

    CertServerHandler(const std::string& ta_key, const std::string& ca_cert, std::shared_ptr<EVP_PKEY> ca_key) : ta_key(ta_key), ca_cert(ca_cert), ca_key(ca_key) {}
};

#endif