#include "build_generator.h"
#include "eval_function.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

unsigned long test_field_reposition(OSSL_LIB_CTX *lib_context) {
    BIGNUM **points = OPENSSL_malloc(3 * sizeof(*points));
    for (int i = 0; i < 3; i++) points[i] = NULL;
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
    for (int i = 0; val && i < 3; i++) {
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
    BIGNUM **points = OPENSSL_zalloc(3 * sizeof(*points));
    BN_dec2bn(&points[0], "1");
    BN_dec2bn(&points[1], "-4");
    BN_dec2bn(&points[2], "1");

    BIGNUM *fm = NULL;
    BN_dec2bn(&fm, "31");

    BIGNUM *x = NULL;
    BN_dec2bn(&x, "2");

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

unsigned long test_build_generator(OSSL_LIB_CTX *lib_context) {
    BIGNUM **function = OPENSSL_zalloc(4 * sizeof(*function));
    BIGNUM **x = OPENSSL_zalloc(4 * sizeof(*x));
    BIGNUM **y = OPENSSL_zalloc(4 * sizeof(*y));
    for (int i = 0; i < 3; i++) {
        x[i] = NULL; y[i] = NULL;
        function[i] = BN_new();
    }
    BN_dec2bn(&x[0], "0"); BN_dec2bn(&y[0], "1");
    BN_dec2bn(&x[1], "2"); BN_dec2bn(&y[1], "-3");
    BN_dec2bn(&x[2], "5"); BN_dec2bn(&y[2], "6");

    BIGNUM *modulus = NULL;
    BN_dec2bn(&modulus, "17");

    unsigned long val = build_generator(
        function,
        x,
        y,
        3,
        modulus,
        lib_context
    );

    printf("Return value = %lu\n", val);
    for (int i = 0; i < 3; i++) {
        char *shifted = BN_bn2dec(function[i]);
        printf("%s\n", shifted);
        OPENSSL_free(shifted);
    }

    BN_free(modulus);

    for (int i = 0; i < 3; i++) {
        BN_free(x[i]); BN_free(y[i]); BN_free(function[i]);
    }
    OPENSSL_free(x);
    OPENSSL_free(y);
    OPENSSL_free(function);
}
