/**
 * @file server.cpp
 */

#include <iostream>
#include <pistache/net.h>
#include <pistache/endpoint.h>
#include <openssl/evp.h>
#include <thread>
#include "handler.hpp"
#include "server.hpp"
#include "exception.hpp"

/**ngat
 * @brief Begin server with specified options.
 * @tested true
 * @throws server_launch_error
 * @param port Port number to start the server on.
 * @param cpu_cores Number of cpu cores to use for the server.
 * @param ta_key Full string data of the OpenVPN ta key.
 * @param ca_cert Full string data of the ca certificate.
 * @param ca_key CA key to sign user certificates with.
 * @returns Server object, so that it can be shutdown later.
 */
std::shared_ptr<Pistache::Http::Endpoint> start_server(int port, int cpu_cores, const std::string& ta_key, const std::string& ca_cert, std::shared_ptr<EVP_PKEY> ca_key)
{
    if(port < 1 || port > 65535)
    {
        throw server_launch_error("Invalid port number!");
    }

    if(cpu_cores < 1 || cpu_cores > std::thread::hardware_concurrency())
    {
        throw server_launch_error("Invalid cpu core count!");
    }

    if(ta_key.empty())
    {
        throw server_launch_error("TA Key is empty!");
    }

    if(ca_cert.empty())
    {
        throw server_launch_error("CA certificate is empty!");
    }

    if(ca_key.get() == nullptr)
    {
        throw server_launch_error("CA key is invalid!");
    }

    Pistache::Address addr(Pistache::Ipv4::any(), port);

    auto server = std::make_shared<Pistache::Http::Endpoint>(addr);

    auto opts = Pistache::Http::Endpoint::options().threads(cpu_cores);

    std::cout << "Starting server on port " << port << " with " << cpu_cores << " cores...\n";

    server->init(opts);
    server->setHandler(Pistache::Http::make_handler<CertServerHandler>(ta_key, ca_cert, ca_key));
    server->serveThreaded();

    return server;
}