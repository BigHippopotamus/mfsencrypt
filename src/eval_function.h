#ifndef _EVAL_FUNCTION_H
#define _EVAL_FUNCTION_H

#include <openssl/bn.h>

int evaluate_function(BIGNUM *r,
                      BIGNUM **function,
                      int function_size,
                      BIGNUM *x,
                      BIGNUM *modulus,
                      BN_RECP_CTX *modulus_context,
                      BN_CTX *context);

#endif
