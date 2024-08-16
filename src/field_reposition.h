#ifndef _FIELD_REPOSITION_H 
#define _FIELD_REPOSITION_H 

#include <openssl/bn.h>

unsigned long field_reposition(BIGNUM **shifted_points,
                               BIGNUM **points, 
                               int count,
                               BIGNUM *field_modulus,
                               BIGNUM *value_modulus,
                               OSSL_LIB_CTX *lib_context);

#endif
