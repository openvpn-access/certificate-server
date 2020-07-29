#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <pistache/endpoint.h>
#include "server.hpp"
#include "exception.hpp"

// start_server()
TEST(StartServer, FailsOnInvalidOptions)
{
    EXPECT_THROW({ start_server(-6, 1, "ta_key", "ca_cert", std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free)); }, server_launch_error);
    EXPECT_THROW({ start_server(5000, 3000, "ta_key", "ca_cert", std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free)); }, server_launch_error);
    EXPECT_THROW({ start_server(5000, 1, "", "ca_cert", std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free)); }, server_launch_error);
    EXPECT_THROW({ start_server(5000, 1, "ta_key", "", std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free)); }, server_launch_error);
    EXPECT_THROW({ start_server(5000, 1, "ta_key", "ca_cert", std::shared_ptr<EVP_PKEY>(nullptr)); }, server_launch_error);
}

TEST(StartServer, StartsWithValidOptions)
{
    std::shared_ptr<Pistache::Http::Endpoint> server;
    ASSERT_NO_THROW({ server = start_server(5000, 1, "ta_key", "ca_cert", std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free)); });

    server->shutdown();
}