#ifndef _BUILD_GENERATOR_H
#define _BUILD_GENERATOR_H

#include <openssl/bn.h>

int field_reposition(BIGNUM **shifted_points,
                     BIGNUM **points, 
                     int count,
                     BIGNUM *field_modulus,
                     BIGNUM *value_modulus,
                     OSSL_LIB_CTX *lib_context);

int build_generator(BIGNUM **generator,
                    BIGNUM **x,
                    BIGNUM **y,
                    int count,
                    BIGNUM *modulus,
                    OSSL_LIB_CTX *lib_context);

#endif
