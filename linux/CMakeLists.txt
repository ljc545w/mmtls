# cmake needs this line
cmake_minimum_required(VERSION 3.1)

# Define project name
project(mmtls)

set(CMAKE_PREFIX_PATH "/usr/bin")

find_package(OpenSSL REQUIRED)
execute_process(
        COMMAND openssl version
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE OPENSSL_VERSION
)
message(STATUS "OpenSSL library status:")
message(STATUS ${OPENSSL_VERSION})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-conversion")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-but-set-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-conversion-null")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-pointer-arith")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format-truncation")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_CXX_STANDARD 17)

include_directories("../src")
include_directories("/usr/include")
link_directories("/usr/lib/x86_64-linux-gnu")

# Declare the executable target built from your sources
add_executable(
    mmtls
    ../src/main.cpp
    ../src/mmtls.cpp
    ../src/mmtls_short.cpp
    ../src/client_hello.cpp
    ../src/server_hello.cpp
    ../src/server_finish.cpp
    ../src/client_finish.cpp
    ../src/record.cpp
    ../src/session.cpp
    ../src/session_ticket.cpp
    ../src/utility.cpp
    ../src/logger.hpp
    ../src/handshakeHasher.cpp
    ../src/signature.cpp
)

# Link your application with OpenSSL libraries
target_link_libraries(mmtls libcrypto.a)
target_link_libraries(mmtls libssl.a)
