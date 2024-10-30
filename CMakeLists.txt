cmake_minimum_required(VERSION 3.12)

project(MultiFileEncryption
    VERSION 0.1
    LANGUAGES C
)

set(SOURCES
    src/mfencrypt.c
    src/build_generator.c
    src/eval_function.c
    src/encode_decode.c
    src/convert_file.c
)

set(DEFINITIONS
    _FILE_OFFSET_BITS=64
)

add_executable(mfencrypt ${SOURCES})

target_compile_definitions(mfencrypt
    PRIVATE
        ${DEFINITIONS}
)

target_include_directories(mfencrypt
    PRIVATE
        include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(mfencrypt
    OpenSSL::SSL
    OpenSSL::Crypto
)

