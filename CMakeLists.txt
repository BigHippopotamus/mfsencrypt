cmake_minimum_required(VERSION 3.12)

project(MultiFileSuperencryption
    VERSION 0.1
    LANGUAGES C
)

set(SOURCES
    src/mfsencrypt.c
    src/build_generator.c
    src/eval_function.c
)

add_executable(mfsencrypt ${SOURCES})

find_package(OpenSSL REQUIRED)
target_link_libraries(mfsencrypt
    OpenSSL::SSL
    OpenSSL::Crypto
)

