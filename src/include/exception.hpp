#ifndef CERTIFICATE_SERVER_EXCEPTION_HPP
#define CERTIFICATE_SERVER_EXCEPTION_HPP

#include <exception>
#include "error.hpp"

class file_not_found_exception : public std::exception {
private:
    std::string error_string;
    std::string path;

public:
    static const error_code code = ERR_FILE_NOT_FOUND;

    const char* what() const noexcept
    {
        return this->error_string.c_str();
    }

    file_not_found_exception(const std::string& path)
    {
        this->path = std::move(path);
        this->error_string = "Unable to find/open file \"" + this->path + "\"!";
    }
};

class rsa_generation_exception : public std::exception {
private:
    const char* error_string;
public:
    static const error_code code = ERR_RSA_GEN;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    rsa_generation_exception(const char* error_string) : error_string(error_string) {}
};

class bad_argument_exception : public std::exception{
private:
    std::string error_string;
    std::string argument;

public:
    static const error_code code = ERR_FILE_NOT_FOUND;

    const char* what() const noexcept
    {
        return this->error_string.c_str();
    }

    bad_argument_exception(const std::string& argument)
    {
        this->argument = std::move(argument);
        this->error_string = "Unrecognized argument \"" + this->argument + "\"!";
    }
};

class failed_signing_exception : public std::exception {
private:
    const char* error_string;

public:
    static const error_code code = ERR_SIGN_FAIL;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    failed_signing_exception(const char* error_string) : error_string(error_string) {}
};

class cert_generation_exception : public std::exception {
private:
    const char* error_string;
public:
    static const error_code code = ERR_RSA_GEN;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    cert_generation_exception(const char* error_string) : error_string(error_string) {}
};

class pem_conversion_exception : public std::exception {
private:
    const char* error_string;
public:
    static const error_code code = ERR_PEM_CONVERT;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    pem_conversion_exception(const char* error_string) : error_string(error_string) {}
};

class pem_load_exception : public std::exception {
private:
    const char* error_string;
public:
    static const error_code code = ERR_PEM_LOAD;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    pem_load_exception(const char* error_string) : error_string(error_string) {}
};

class server_launch_error : public std::exception {
private:
    const char* error_string;
public:
    static const error_code code = ERR_PEM_LOAD;

    const char* what() const noexcept
    {
        return this->error_string;
    }

    server_launch_error(const char* error_string) : error_string(error_string) {}
};

#endif //CERTIFICATE_SERVER_EXCEPTION_HPP
