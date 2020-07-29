#ifndef CERTIFICATE_SERVER_MAIN_HPP
#define CERTIFICATE_SERVER_MAIN_HPP

void print_help();
std::string read_file(const std::string& path);
std::map<std::string, std::string> parse_arguments(int argc, char const** argv);

#endif //CERTIFICATE_SERVER_MAIN_HPP
