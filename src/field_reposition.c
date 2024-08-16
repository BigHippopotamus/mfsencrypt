#include "field_reposition.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

unsigned long field_reposition(BIGNUM **shifted_points,
                               BIGNUM **points, 
                               int count,
                               BIGNUM *field_modulus,
                               BIGNUM *value_modulus,
                               OSSL_LIB_CTX *lib_context) {
    BN_CTX *context = NULL;
    BIGNUM *modulus_quotient = NULL, *modulus_remainder = NULL;
    BIGNUM *modulus_quotient_plus_one = NULL, *shift_amt = NULL;

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error;

    int success;
    
    modulus_quotient = BN_new();
    if (!modulus_quotient) goto handle_error;

    modulus_remainder = BN_new();
    if (!modulus_remainder) goto handle_error;

    modulus_quotient_plus_one = BN_new();
    if (!modulus_quotient_plus_one) goto handle_error;

    success = BN_div(modulus_quotient,
                     modulus_remainder,
                     field_modulus,
                     value_modulus,
                     context);
    if (!success) goto handle_error;

    success = 
        BN_add(modulus_quotient_plus_one, modulus_quotient, BN_value_one());
    if (!success) goto handle_error;

    shift_amt = BN_new();
    if (!shift_amt) goto handle_error;

    for (int i = 0; i < count; i++) {
        int less_than = BN_cmp(points[i], modulus_remainder) < 0;

        BIGNUM *shift_max = less_than ? 
            modulus_quotient_plus_one : 
            modulus_quotient;
        BN_rand_range(shift_amt, shift_max);

        success = BN_mul(shift_amt, shift_amt, value_modulus, context);
        if (!success) goto handle_error;

        success = BN_add(shifted_points[i], points[i], shift_amt);
        if (!success) goto handle_error;
    }

    BN_free(shift_amt);

    BN_free(modulus_quotient_plus_one);
    BN_free(modulus_remainder);
    BN_free(modulus_quotient);

    BN_CTX_free(context);

    return 0;

handle_error:
    BN_free(shift_amt);

    BN_free(modulus_quotient_plus_one);
    BN_free(modulus_remainder);
    BN_free(modulus_quotient);

    BN_CTX_free(context);

    for (int i = 0; i < count; i++) {
        BN_free(shifted_points[i]);
        shifted_points[i] = NULL;
    }

    int last_error = 0;
    while (last_error = ERR_get_error());
    return last_error;
}
