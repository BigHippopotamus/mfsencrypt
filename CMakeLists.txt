cmake_minimum_required(VERSION 3.12)

project(MultiFileSuperencryption
    VERSION 0.1
    LANGUAGES C
)

set(SOURCES
    src/mfsencrypt.c
    src/build_generator.c
    src/eval_function.c
    src/encode_decode.c
    src/convert_file.c
)

set(DEFINITIONS
    _FILE_OFFSET_BITS=64
)

add_executable(mfsencrypt ${SOURCES})

target_compile_definitions(mfsencrypt
    PRIVATE
        ${DEFINITIONS}
)

target_include_directories(mfsencrypt
    PRIVATE
        include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(mfsencrypt
    OpenSSL::SSL
    OpenSSL::Crypto
)

