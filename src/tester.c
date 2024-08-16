#include "field_reposition.h"
#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

unsigned long test_field_reposition(OSSL_LIB_CTX *lib_context) {
    BIGNUM **points = OPENSSL_malloc(3 * sizeof(*points));
    BN_dec2bn(&points[0], "127");
    BN_dec2bn(&points[1], "255");
    BN_dec2bn(&points[2], "31");

    BIGNUM *fm = NULL, *vm = NULL;
    BN_dec2bn(&fm, "1087");
    BN_dec2bn(&vm, "256");

    BIGNUM **shifted_points = OPENSSL_zalloc(3 * sizeof(shifted_points));
    for (int i = 0; i < 3; i++)
        shifted_points[i] = BN_new();

    unsigned long val = field_reposition(
        shifted_points,
        points,
        3,
        fm,
        vm,
        lib_context
    );

    printf("Return value: %lu\n", val);
    for (int i = 0; i < 3; i++) {
        char *shifted = BN_bn2dec(shifted_points[i]);
        printf("%s\n", shifted);
        OPENSSL_free(shifted);
    }

    BN_free(fm);
    BN_free(vm);
    for (int i = 0; i < 3; i++) {
        BN_free(shifted_points[i]);
        BN_free(points[i]);
    }
    OPENSSL_free(shifted_points);
    OPENSSL_free(points);

    return 0;
}

unsigned long test_eval_function(OSSL_LIB_CTX *lib_context) {
    BIGNUM **points = OPENSSL_malloc(3 * sizeof(*points));
    BN_dec2bn(&points[0], "20");
    BN_dec2bn(&points[1], "5");
    BN_dec2bn(&points[2], "2");

    BIGNUM *fm = NULL;
    BN_dec2bn(&fm, "31");

    BIGNUM *x = NULL;
    BN_dec2bn(&x, "5");

    BIGNUM *result = BN_new();

    BN_CTX *context = BN_CTX_new_ex(lib_context);
    BN_RECP_CTX *modulus_context = BN_RECP_CTX_new();
    BN_RECP_CTX_set(modulus_context, fm, context);

    unsigned long val = evaluate_function(
        result,
        points,
        3,
        x,
        fm,
        modulus_context,
        context
    );

    printf("Return value: %lu\n", val);
    char *shifted = BN_bn2dec(result);
    printf("%s\n", shifted);
    OPENSSL_free(shifted);

    BN_RECP_CTX_free(modulus_context);
    BN_CTX_free(context);

    BN_free(result);
    BN_free(x);
    BN_free(fm);
    for (int i = 0; i < 3; i++) {
        BN_free(points[i]);
    }
    OPENSSL_free(points);

    return 0;
}
