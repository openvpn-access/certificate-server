#ifndef CERTIFICATE_SERVER_SERVER_HPP
#define CERTIFICATE_SERVER_SERVER_HPP

#include <thread>
#include <pistache/endpoint.h>

std::shared_ptr<Pistache::Http::Endpoint> start_server(int port, int cpu_cores, const std::string& ta_key, const std::string& ca_cert, std::shared_ptr<EVP_PKEY> ca_key);

#endif //CERTIFICATE_SERVER_SERVER_HPP
