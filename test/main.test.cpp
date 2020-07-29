#include <gtest/gtest.h>
#include <iostream>
#include <fstream>
#include "main.hpp"
#include "exception.hpp"

// print_help()
TEST(PrintHelp, DoesNotThrow)
{
    ASSERT_NO_THROW({ print_help(); });
}

// read_file()
TEST(ReadFile, ReadsFiles)
{
    std::string test_string = "this\nis\na\tstring!\n";
    const char* path = "__cert_server_read_file_test.txt";

    std::ofstream test_file(path);
    test_file << test_string;
    test_file.close();

    EXPECT_EQ(test_string, read_file(path));

    std::remove(path);
}

TEST(ReadFile, FailsOnBadPath)
{
    ASSERT_THROW({ read_file("this_path_does_not_exist.txt"); }, file_not_found_exception);
}

// parse_arguments()
TEST(ParseArguments, ReturnDefaultValues)
{
    std::map<std::string, std::string> my_args = parse_arguments(0, nullptr);
}

TEST(ParseArguments, FailOnBadValues)
{
    const char* args1[] = {".", "--bad_arg"};
    ASSERT_THROW({ parse_arguments(2, args1); }, bad_argument_exception);

    const char* args2[] = {".", "--bad_arg", "asdf", "52hkd", "4234d"};
    ASSERT_THROW({ parse_arguments(5, args2); }, bad_argument_exception);
}

TEST(ParseArguments, AllowCorrectValues)
{
    const char* args[] = {".", "--port=3000", "--cpu_cores=100", "--ca_cert=crt.crt", "--ca_key=ca.pem", "--ta=ta.key"};

    std::map<std::string, std::string> parsed_args;
    ASSERT_NO_THROW({ parsed_args = parse_arguments(6, args); });

    EXPECT_EQ(parsed_args["port"], "3000");
    EXPECT_EQ(parsed_args["cpu_cores"], "100");
    EXPECT_EQ(parsed_args["ca_cert"], "crt.crt");
    EXPECT_EQ(parsed_args["ca_key"], "ca.pem");
    EXPECT_EQ(parsed_args["ta"], "ta.key");
}