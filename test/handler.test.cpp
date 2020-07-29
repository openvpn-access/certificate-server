#include <memory>
#include <openssl/evp.h>
#include <pistache/endpoint.h>
#include <pistache/client.h>
#include <pistache/http.h>
#include <pistache/net.h>
#include <nlohmann/json.hpp>
#include <gtest/gtest.h>
#include <thread>
#include "config.hpp"
#include "server.hpp"

class HandlerTest : public ::testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// onRequest()
TEST_F(HandlerTest, HandlesInvalidEndpoints)
{
}

TEST_F(HandlerTest, RejectsInvalidMethods)
{
}

TEST_F(HandlerTest, ReturnsProperVersion)
{
}
