#ifndef _ENCODE_DECODE_H
#define _ENCODE_DECODE_H

#include <openssl/bn.h>

int encode_data(BIGNUM **generator,
                BIGNUM **x,
                BIGNUM **y,
                int count,
                BIGNUM *field,
                BIGNUM *value_mod,
                OSSL_LIB_CTX *lib_context);

int decode_data(BIGNUM *result,
                BIGNUM **generator,
                BIGNUM *x,
                int generator_size,
                BIGNUM *field,
                BIGNUM *value_mod,
                OSSL_LIB_CTX *lib_context);

#endif
