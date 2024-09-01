#include "encode_decode.h"
#include "build_generator.h"
#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>

int encode_block(BIGNUM *generator[],
                 BIGNUM *x[],
                 BIGNUM *y[],
                 int count,
                 BIGNUM *field,
                 BIGNUM *value_mod,
                 OSSL_LIB_CTX *lib_context) {
    int return_value = 1;

    BN_CTX *context = NULL;
    BIGNUM **shifted_y = NULL;

    int success;

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error;

    shifted_y = OPENSSL_zalloc(count * sizeof(*shifted_y));
    if (!shifted_y) goto handle_error;

    for (int i = 0; i < count; i++) {
        shifted_y[i] = BN_new();
        if (!shifted_y[i]) goto handle_error;
    }

    success = field_reposition(
        shifted_y,
        y,
        count,
        field,
        value_mod,
        context
    );
    if (!success) goto handle_error;

    success = build_generator(
        generator,
        x,
        shifted_y,
        count,
        field,
        context
    );
    if (!success) goto handle_error;

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    for (int i = 0; i < count; i++) {
        BN_free(shifted_y[i]);
    }
    OPENSSL_free(shifted_y);

    BN_CTX_free(context);

    return return_value;
}

int decode_block(BIGNUM *result,
                 BIGNUM *generator[],
                 BIGNUM *x,
                 int generator_size,
                 BIGNUM *field,
                 BIGNUM *value_mod,
                 OSSL_LIB_CTX *lib_context) {
    int return_value = 1;

    BN_CTX *context = NULL;
    BN_RECP_CTX *modulus_context = NULL;
    BIGNUM *generator_output = NULL;

    int success;

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error;

    modulus_context = BN_RECP_CTX_new();
    if (!modulus_context) goto handle_error;

    success = BN_RECP_CTX_set(modulus_context, field, context);
    if (!success) goto handle_error;

    generator_output = BN_new();
    if (!generator_output) goto handle_error;

    success = evaluate_function(
        generator_output,
        generator,
        generator_size,
        x,
        field,
        modulus_context,
        context
    );
    if (!success) goto handle_error;

    success = BN_nnmod(
        result,
        generator_output,
        value_mod,
        context
    );
    if (!success) goto handle_error;

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    BN_free(generator_output);

    BN_RECP_CTX_free(modulus_context);

    BN_CTX_free(context);

    return return_value;
}
