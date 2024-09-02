#include "build_generator.h"
#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>

#define RAND_STRENGTH 256

int field_reposition(BIGNUM *shifted_points[],
                     BIGNUM *points[],
                     int count,
                     BIGNUM *field_modulus,
                     BIGNUM *value_modulus,
                     BN_CTX *context) {
    int return_value = 1;

    BIGNUM *modulus_quotient = NULL, *modulus_remainder = NULL;
    BIGNUM *modulus_quotient_plus_one = NULL, *shift_amt = NULL;

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

        success = BN_rand_range_ex(
            shift_amt, 
            shift_max,
            RAND_STRENGTH,
            context
        );
        if (!success) goto handle_error;

        success = BN_mul(shift_amt, shift_amt, value_modulus, context);
        if (!success) goto handle_error;

        success = BN_add(shifted_points[i], points[i], shift_amt);
        if (!success) goto handle_error;
    }

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    BN_free(shift_amt);

    BN_free(modulus_quotient_plus_one);
    BN_free(modulus_remainder);
    BN_free(modulus_quotient);

    return return_value;
}

int build_generator(BIGNUM *generator[],
                    BIGNUM *x[],
                    BIGNUM *y[],
                    int count,
                    BIGNUM *modulus,
                    BN_CTX *context) {
    int return_value = 1;

    BN_RECP_CTX *modulus_context = NULL;
    BIGNUM **support_function = NULL;
    BIGNUM *value_difference = NULL, *lambda = NULL;
    BIGNUM *temp_a = NULL, *temp_b = NULL;

    int success;

    success = (BN_copy(generator[0], y[0]) != NULL);
    if (!success) goto handle_error;

    if (count <= 1) return return_value;

    // Reset generator values
    for (int i = 1; i < count; i++) {
        BN_zero(generator[i]);
    }

    modulus_context = BN_RECP_CTX_new();
    if (!modulus_context) goto handle_error;
    
    success = BN_RECP_CTX_set(modulus_context, modulus, context);
    if (!success) goto handle_error;

    value_difference = BN_new();
    if (!value_difference) goto handle_error;

    lambda = BN_new();
    if (!lambda) goto handle_error;

    temp_a = BN_new();
    if (!temp_a) goto handle_error;

    temp_b = BN_new();
    if (!temp_b) goto handle_error;

    // Initialize support function
    support_function 
        = OPENSSL_zalloc(count * sizeof(*support_function));
    if (!support_function) goto handle_error;

    for (int i = 0; i < count; i++) {
        support_function[i] = BN_new();
        if (!support_function[i]) goto handle_error;
    }

    success = BN_mod_sub(
        support_function[0],
        modulus, 
        x[0], 
        modulus, 
        context
    );
    if (!success) goto handle_error;
    
    success = (BN_copy(support_function[1], BN_value_one()) != NULL);
    if (!success) goto handle_error;

    // Start making the generator
    for (int i = 1; i < count; i++) {
        success = evaluate_function(
            temp_a,
            generator,
            i,
            x[i],
            modulus,
            modulus_context,
            context
        );
        if (!success) goto handle_error;

        success = BN_mod_sub(
            value_difference, 
            y[i], 
            temp_a,
            modulus,
            context
        );
        if (!success) goto handle_error;

        success = evaluate_function(
            temp_a,
            support_function,
            i + 1,
            x[i],
            modulus,
            modulus_context,
            context
        );
        if (!success) goto handle_error;

        success = (BN_mod_inverse(temp_a, temp_a, modulus, context) != NULL);
        if (!success) goto handle_error;

        success = BN_mod_mul_reciprocal(
            lambda, 
            value_difference, 
            temp_a, 
            modulus_context, 
            context
        );
        if (!success) goto handle_error;

        // Update generator
        for (int j = i; j >= 0; j--) {
            success = BN_mod_mul_reciprocal(
                temp_a,
                lambda,
                support_function[j],
                modulus_context,
                context
            );
            if (!success) goto handle_error;

            success = BN_mod_add(
                temp_b,
                generator[j],
                temp_a,
                modulus,
                context
            );
            if (!success) goto handle_error;

            success = (BN_copy(generator[j], temp_b) != NULL);
            if (!success) goto handle_error;
        }

        // Update support function 
        if (i + 1 < count) {
            for (int j = i + 1; j >= 0; j--) {
                success = BN_mod_sub(
                    temp_a, 
                    modulus, 
                    x[i],
                    modulus,
                    context
                );
                if (!success) goto handle_error;

                success = BN_mod_mul_reciprocal(
                    temp_b,
                    support_function[j],
                    temp_a,
                    modulus_context,
                    context
                );
                if (!success) goto handle_error;

                if (j != 0) {
                    success = BN_mod_add(
                        support_function[j],
                        temp_b,
                        support_function[j - 1],
                        modulus,
                        context
                    );
                    if (!success) goto handle_error;
                } else {
                    success = (BN_copy(support_function[j], temp_b) != NULL);
                    if (!success) goto handle_error;
                }
            }
        }
    }

    // Reduce the bits used to store the generator
    for (int i = 0; i < count; i++) {
        success = BN_sub(temp_a, generator[i], modulus);
        if (!success) goto handle_error;

        if (BN_num_bits(temp_a) < BN_num_bits(generator[i])) {
            success = (BN_copy(generator[i], temp_a) != NULL);
            if (!success) goto handle_error;
        }
    }

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    BN_free(temp_b);
    BN_free(temp_a);
    
    BN_free(lambda);
    BN_free(value_difference);

    if (support_function) {
        for (int i = 0; i < count; i++) {
            BN_free(support_function[i]);
            support_function[i] = NULL;
        }
    }
    OPENSSL_free(support_function);

    BN_RECP_CTX_free(modulus_context);

    return return_value;
}
