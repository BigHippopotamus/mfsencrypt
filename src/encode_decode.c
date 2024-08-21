#include "encode_decode.h"
#include "build_generator.h"
#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>

#define FIELD_MOD "62b550139847676de987d98f9cc32c73d38f1a7969285cb18acb9689fb824bb75"
#define VALUE_MOD "10000000000000000"  // 2^64

int encode_data(BIGNUM **generator,
                BIGNUM **x,
                BIGNUM **y,
                int count,
                BIGNUM *field,
                BIGNUM *value_mod,
                OSSL_LIB_CTX *lib_context) {
    BN_CTX *context = NULL;
    BIGNUM **shifted_y = NULL;

    int success;

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error_ed;

    shifted_y = OPENSSL_zalloc(count * sizeof(*shifted_y));
    if (!shifted_y) goto handle_error_ed;

    for (int i = 0; i < count; i++) {
        shifted_y[i] = BN_new();
        if (!shifted_y[i]) goto handle_error_ed;
    }

    success = field_reposition(
        shifted_y,
        y,
        count,
        field,
        value_mod,
        context
    );
    if (!success) goto handle_error_ed;

    success = build_generator(
        generator,
        x,
        shifted_y,
        count,
        field,
        context
    );
    if (!success) goto handle_error_ed;

    for (int i = 0; i < count; i++) {
        BN_free(shifted_y[i]);
    }
    OPENSSL_free(shifted_y);

    BN_CTX_free(context);

    return 1;

handle_error_ed:
    for (int i = 0; i < count; i++) {
        BN_free(shifted_y[i]);
    }
    OPENSSL_free(shifted_y);

    BN_CTX_free(context);

    return 0;
}

int decode_data(BIGNUM *result,
                BIGNUM **generator,
                BIGNUM *x,
                int generator_size,
                BIGNUM *field,
                BIGNUM *value_mod,
                OSSL_LIB_CTX *lib_context) {
    BN_CTX *context = NULL;
    BN_RECP_CTX *modulus_context = NULL;
    BIGNUM *generator_output = NULL;

    int success;

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error_dd;

    modulus_context = BN_RECP_CTX_new();
    if (!modulus_context) goto handle_error_dd;

    success = BN_RECP_CTX_set(modulus_context, field, context);
    if (!success) goto handle_error_dd;

    generator_output = BN_new();
    if (!generator_output) goto handle_error_dd;

    success = evaluate_function(
        generator_output,
        generator,
        generator_size,
        x,
        field,
        modulus_context,
        context
    );
    if (!success) goto handle_error_dd;

    success = BN_nnmod(
        result,
        generator_output,
        value_mod,
        context
    );
    if (!success) goto handle_error_dd;

    BN_free(generator_output);

    BN_RECP_CTX_free(modulus_context);

    BN_CTX_free(context);

    return 1;

handle_error_dd:
    BN_free(generator_output);

    BN_RECP_CTX_free(modulus_context);

    BN_CTX_free(context);

    return 0;
}
