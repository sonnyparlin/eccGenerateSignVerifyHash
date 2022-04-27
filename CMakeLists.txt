cmake_minimum_required(VERSION 3.0.0)

project(eccGenerateSignVerifyHash VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 14)


if(UNIX)
    include_directories(include /usr/local/include /usr/local/opt/openssl@3/include)
    set (OPENSSL_ROOT_DIR /usr/local/opt/openssl@3)
    include(FindOpenSSL)
    find_package(OpenSSL REQUIRED)

    if (OPENSSL_FOUND)
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
    else() 
    message (FATAL_ERROR "OpenSSL Not found.")
    endif()

    add_executable(eccGenerateSignVerifyHash eccExample.cpp)
    SET(CMAKE_CXX_FLAGS "-Wall -std=c++14")
    target_link_libraries(eccGenerateSignVerifyHash PUBLIC OpenSSL::Crypto)
endif(UNIX)

if (MINGW)
    set(OPENSSL_ROOT_DIR "C:\\OpenSSL-Win64\\")
    include(FindOpenSSL)

    add_executable(eccGenerateSignVerifyHash eccExample.cpp)

    SET(CMAKE_CXX_FLAGS "-Wall -std=c++14")

    if (OPENSSL_FOUND)
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
    else() 
    message (FATAL_ERROR "OpenSSL Not found.")
    endif()

    target_link_libraries(
    eccGenerateSignVerifyHash 
    PUBLIC 
    "C:\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll"
    "C:\\OpenSSL-Win64\\bin\\libssl-3-x64.dll"
    bcrypt)
endif(MINGW)