cmake_minimum_required(VERSION 3.25)

project(
    ssc
    VERSION 0.0.1
    LANGUAGES C
)

find_package(OpenSSL REQUIRED)
find_package(BLAKE3 REQUIRED)
find_package(libuv REQUIRED)

set(SSC_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_library(
    config
    SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/config.c"
)

add_executable(
    ssc-local
    "${SSC_SRC_DIR}/local_build.c"
)
target_link_libraries(
    ssc-local
    PRIVATE
    OpenSSL::Crypto
    "$<IF:$<BOOL:${WIN32}>,libuv::uv,libuv::uv_a>"
    BLAKE3::blake3
)
target_include_directories(ssc-local PRIVATE "${SSC_SRC_DIR}")
target_compile_definitions(ssc-local PRIVATE SSC_CRYPTO_OPENSSL)
set_property(TARGET ssc-local PROPERTY C_STANDARD 11)
