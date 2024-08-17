#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/err.h>

int evaluate_function(BIGNUM *r,
                      BIGNUM **function,
                      int function_size,
                      BIGNUM *x,
                      BIGNUM *modulus,
                      BN_RECP_CTX *modulus_context,
                      BN_CTX *context) {
    BIGNUM *accumulator_a = NULL, *accumulator_b = NULL;
    BIGNUM *temp = NULL, *alt_result = NULL;

    BN_zero(r);

    int success;

    accumulator_a = BN_dup(BN_value_one());
    if (!accumulator_a) goto handle_error;

    accumulator_b = BN_new();
    if (!accumulator_b) goto handle_error;

    temp = BN_new();
    if (!temp) goto handle_error;

    alt_result = BN_new();
    if (!alt_result) goto handle_error;

    for (int i = 0; i < function_size; i++) {
        BIGNUM *accumulator = (i % 2 == 0) ? accumulator_a : accumulator_b;
        success = BN_mod_mul_reciprocal(
            temp,
            function[i],
            accumulator,
            modulus_context,
            context
        );
        if (!success) goto handle_error;

        BIGNUM *add_from = (i % 2 == 0) ? r : alt_result;
        BIGNUM *add_to = (i % 2 == 0) ? alt_result : r;

        success = BN_mod_add(
            add_to,
            add_from,
            temp,
            modulus,
            context
        );
        if (!success) goto handle_error;

        BIGNUM *next_accumulator = 
            (i % 2 == 0) ? accumulator_b : accumulator_a;

        success = BN_mod_mul_reciprocal(
            next_accumulator,
            accumulator,
            x,
            modulus_context,
            context
        );
        if (!success) goto handle_error;
    }

    if (function_size % 2 != 0) {
        success = (BN_copy(r, alt_result) != NULL);
        if (!success) goto handle_error;
    }

    BN_free(temp);

    BN_free(alt_result);

    BN_free(accumulator_a);
    BN_free(accumulator_b);

    return 1;

handle_error:
    BN_free(temp);

    BN_free(alt_result);

    BN_free(accumulator_a);
    BN_free(accumulator_b);

    return 0;
}
