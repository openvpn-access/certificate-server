cmake_minimum_required(VERSION 3.16)
project(certificate_server VERSION "0.1.0")

set(CMAKE_CXX_STANDARD 20)

# Options
option(BUILD_TESTS "Build certificate_server tests" ON)
option(RUN_TESTS "Run certificate_server tests" ON)
option(GENERATE_DOCUMENTATION "Generate documentation" ON)

# Main executable
set(CERTIFICATE_SERVER_SOURCES
        src/server.cpp
        src/handler.cpp
        src/crypto.cpp
        src/main.cpp)
set(CERTIFICATE_SERVER_INCLUDES
        src/include
        ${PROJECT_BINARY_DIR})

configure_file(src/include/config.hpp.in ${PROJECT_BINARY_DIR}/config.hpp)

add_executable(certificate_server
        ${CERTIFICATE_SERVER_SOURCES})
target_include_directories(certificate_server PRIVATE
        ${CERTIFICATE_SERVER_INCLUDES})
target_link_libraries(certificate_server pthread)

# Documentation
add_custom_target(documentation
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMAND doxygen)

if(GENERATE_DOCUMENTATION)
    add_dependencies(certificate_server documentation)
endif()

# Testing
if(BUILD_TESTS)
    set(TEST_SOURCES
            test/main.test.cpp test/server.test.cpp test/handler.test.cpp)

    add_executable(certificate_server-tests ${CERTIFICATE_SERVER_SOURCES} ${TEST_SOURCES})
    target_compile_definitions(certificate_server-tests PUBLIC -DTESTING)
    target_include_directories(certificate_server-tests PRIVATE ${CERTIFICATE_SERVER_INCLUDES})
    target_link_libraries(certificate_server-tests pthread)

    add_dependencies(certificate_server certificate_server-tests)

    if(RUN_TESTS)
        add_custom_command(TARGET certificate_server POST_BUILD
                WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                COMMAND ./certificate_server-tests)
    endif()
endif()

# Allow us to download dependencies
include(FetchContent)

# Grab googletest
if(BUILD_TESTS)
    FetchContent_Declare(googletest
            GIT_REPOSITORY  https://github.com/google/googletest.git
            GIT_TAG master)

    FetchContent_MakeAvailable(googletest)

    target_include_directories(certificate_server-tests PUBLIC SYSTEM ${googletest_SOURCE_DIR}/googletest/include)
    target_link_libraries(certificate_server-tests gtest)
endif()

# Link against openssl
find_library(OPENSSL NAMES openssl ssl libopenssl REQUIRED)
find_library(CRYPTO NAMES crypto libcrypto REQUIRED)

target_link_libraries(certificate_server ${OPENSSL})
target_link_libraries(certificate_server ${CRYPTO})

if(BUILD_TESTS)
    target_link_libraries(certificate_server-tests ${OPENSSL})
    target_link_libraries(certificate_server-tests ${CRYPTO})
endif()

# Link against pistache
find_library(PISTACHE NAMES pistache libpistache REQUIRED)

target_link_libraries(certificate_server ${PISTACHE})

if(BUILD_TESTS)
    target_link_libraries(certificate_server-tests ${PISTACHE})
endif()

# Grab JSON
FetchContent_Declare(json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.7.3)

FetchContent_MakeAvailable(json)

target_include_directories(certificate_server PUBLIC SYSTEM ${json_SOURCE_DIR}/single_include)
target_link_libraries(certificate_server nlohmann_json::nlohmann_json)

if(BUILD_TESTS)
    target_include_directories(certificate_server-tests PUBLIC SYSTEM ${json_SOURCE_DIR}/single_include)
    target_link_libraries(certificate_server-tests nlohmann_json::nlohmann_json)
endif()