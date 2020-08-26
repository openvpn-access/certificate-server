/**
 * @file handler.cpp
 */

#include <pistache/net.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <memory>
#include <iostream>
#include <nlohmann/json.hpp>
#include "handler.hpp"
#include "crypto.hpp"
#include "exception.hpp"
#include "config.hpp"

/**
 * @brief Handler to process all HTTP requests to the server.
 * @tested false
 * @param req Request object.
 * @param response Response object.
 */
void CertServerHandler::onRequest(const Pistache::Http::Request &req, Pistache::Http::ResponseWriter response)
{
    response.headers().add<Pistache::Http::Header::ContentType>(MIME(Application, Json));

    if(req.resource() == "/certificate" && req.method() == Pistache::Http::Method::Post)
    {
        nlohmann::json body = nlohmann::json::parse(req.body());

        if(!body.contains("rsaBits") || !body["rsaBits"].is_number()
        || !body.contains("username") || !body["username"].is_string())
        {
            response.send(Pistache::Http::Code::Bad_Request);
            return;
        }

        try
        {
            std::shared_ptr<EVP_PKEY> rsa_key = generate_rsa_keypair(body["rsaBits"].get<int>());
            std::shared_ptr<rsa_keypair_t> key_pair = get_keypair_data(rsa_key);

            std::string private_pem = key_pair->private_key.substr(0, key_pair->private_key.find("-----END PRIVATE KEY-----") + 25);

            std::shared_ptr<X509> user_certificate = generate_user_cert(rsa_key, body["username"].get<std::string>().c_str());
            sign_user_x509(user_certificate, this->ca_key);

            std::string user_cert_data = get_x509_data(user_certificate);

            nlohmann::json response_body = {
                    {"key", private_pem},
                    {"ca", this->ca_cert},
                    {"tls", this->ta_key},
                    {"cert", user_cert_data}
            };
            response.send(Pistache::Http::Code::Ok, response_body.dump());
        }
        catch(const rsa_generation_exception& e)
        {
            nlohmann::json response_body = { {"errorMessage", e.what()} };
            response.send(Pistache::Http::Code::Internal_Server_Error, response_body.dump());
            return;
        }
        catch(const std::exception& e)
        {
            nlohmann::json response_body = { {"errorMessage", e.what()} };
            response.send(Pistache::Http::Code::Internal_Server_Error, response_body.dump());
            return;
        }
        catch(...)
        {
            response.send(Pistache::Http::Code::Internal_Server_Error);
            return;
        }
    }
    else if(req.resource() == "/version" && req.method() == Pistache::Http::Method::Get)
    {
        std::string version_string((std::string)"v" + PROJECT_VER_MAJOR + "." + PROJECT_VER_MINOR + "." + PROJECT_VER_PATCH);

        nlohmann::json response_body = { {"version", version_string} };
        response.send(Pistache::Http::Code::Ok, response_body.dump());
    }
    else
    {
        response.send(Pistache::Http::Code::Bad_Request);
    }
}