cmake_minimum_required(VERSION 3.16)
project(fips_file_crypt CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(OpenSSL 3.0 REQUIRED)

add_executable(fips_file_crypt src/main.cpp)
target_link_libraries(fips_file_crypt PRIVATE OpenSSL::Crypto)
target_compile_options(fips_file_crypt PRIVATE -Wall -Wextra)
