/**
 * @file main.cpp
 */

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <map>
#include <filesystem>
#include <exception>
#include <openssl/evp.h>
#include <unistd.h>
#include <cstdlib>
#include <csignal>
#include <pistache/endpoint.h>
#include "main.hpp"
#include "server.hpp"
#include "crypto.hpp"
#include "exception.hpp"
#include "config.hpp"

/**
 * @brief Prints certificate_server help text to console.
 * @tested true
 */
void print_help()
{
    std::cout << "OpenVPN Access Certificate Server v" << PROJECT_VER_MAJOR << "." << PROJECT_VER_MINOR << "." << PROJECT_VER_PATCH << std::endl;
}

/**
 * @brief Read a file from a path and return its contents as a string.
 * @tested true
 * @throws file_not_found_exception
 * @param path Path to the file.
 * @return The entire string contents of the file.
 */
std::string read_file(const std::string& path)
{
    std::string file_raw;

    std::string line;
    std::ifstream file(path);
    if(file.is_open())
    {
        while(std::getline(file, line))
        {
            file_raw.append(line + '\n');
        }
        file.close();
    }
    else
    {
        throw file_not_found_exception(path);
    }

    return file_raw;
}

/**
 * @brief Parse command line arguments, filling in their default values and returning them as an std::map.
 *
 * If nullptr is passed to argv, the default options are returned and the executable directory is assumed to be
 * the current parent working directory.
 *
 * @tested true
 * @throws bad_argument_exception
 * @param argc Straight arg count throughput from `main`.
 * @param argv Straight argument throughput from `main`.
 * @return Map of the parsed command line options.
 */
std::map<std::string, std::string> parse_arguments(int argc = 0, char const** argv = nullptr)
{
    // Process command line args
    std::map<std::string, std::string> arguments;

    arguments["port"] = std::to_string(5000);
    arguments["cpu_cores"] = std::to_string(std::thread::hardware_concurrency());

    std::filesystem::path executable_path;
    if(argv == nullptr)
    {
        executable_path = ".";
    }
    else
    {
        executable_path = argv[0];
    }

    arguments["ca_cert"] = (std::string) (executable_path / "pki/crt/ca.crt");
    arguments["ca_key"] = (std::string) (executable_path / "pki/private/ca.pem");
    arguments["ta"] = (std::string) (executable_path / "pki/ta.key");

    for(int i = 1; i < argc; i++)
    {
        std::string argument(argv[i]);

        if(argument.starts_with("--"))
        {
            int split = argument.find_first_of('=');
            std::string key = argument.substr(2, split - 2);
            std::string value = argument.substr(split + 1);

            if(arguments.count(key))
            {
                arguments[key] = value;

                continue;
            }
        }

        throw bad_argument_exception(argument);
    }

    return arguments;
}

#ifndef TESTING
/**
 * @brief Certificate Server entrypoint.
 */
int main(int argc, char const** argv)
{
    if(argc <= 1)
    {
        print_help();
        return 0;
    }

    std::shared_ptr<Pistache::Http::Endpoint> server;

    try
    {
        std::map<std::string, std::string> arguments = parse_arguments(argc, argv);

        initialize_crypto();

        std::string ta_key = read_file(arguments["ta"]);
        std::string ca_cert = read_file(arguments["ca_cert"]);
        std::shared_ptr<EVP_PKEY> ca_key = load_private_key_file(arguments["ca_key"].c_str());

        server = start_server(std::stoi(arguments["port"]),
                     std::stoi(arguments["cpu_cores"]) || std::thread::hardware_concurrency(),
                     ta_key,
                     ca_cert,
                     ca_key);

        std::cout << "Server started!\n";

        // Listen for quit signals, so that we can unbind the server before quitting.
        // This prevents errors that stem from ports still being bound.
        struct sigaction sigIntHandler;

        sigIntHandler.sa_handler = [](int s) {
            std::cout << "\nShutting down server (signal " << s << ")...\n";
        };
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;

        sigaction(SIGINT, &sigIntHandler, NULL);
        sigaction(SIGABRT, &sigIntHandler, NULL);
        sigaction(SIGKILL, &sigIntHandler, NULL);
        sigaction(SIGQUIT, &sigIntHandler, NULL);
        sigaction(SIGTERM, &sigIntHandler, NULL);

        pause();
    }
    catch(const bad_argument_exception& e)
    {
        std::cerr << e.what() << std::endl;
        print_help();
        return 1;
    }
    catch(const file_not_found_exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    catch(...)
    {
        std::cerr << "Encountered fatal server error!\n";
        return 1;
    }

    if(server)
    {
        server->shutdown();
        std::cout << "Server shutdown!\n";
    }

    crypto_cleanup();

    return 0;
}
#else
#include <gtest/gtest.h>

/**
 * @brief Entrypoint for certificate server tests.
 */
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
#endif
