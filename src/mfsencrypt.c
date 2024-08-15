#include "field_reposition.h"
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>

unsigned long test_field_reposition(OSSL_LIB_CTX *lib_context) {
    BIGNUM **points = OPENSSL_malloc(3 * sizeof(*points));
    BN_dec2bn(&points[0], "6");
    BN_dec2bn(&points[1], "3");
    BN_dec2bn(&points[2], "0");

    BIGNUM *fm = NULL, *vm = NULL;
    BN_dec2bn(&fm, "31");
    BN_dec2bn(&vm, "9");

    BIGNUM **shifted_points = NULL;
    unsigned long val = field_reposition(
        &shifted_points,
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
}

int main() {
    //while (!BN_poll());

    OSSL_LIB_CTX *lib_context;
    lib_context = OSSL_LIB_CTX_new();

    if (!lib_context) goto handle_error;

    test_field_reposition(lib_context);

    return 0;

handle_error:
    //return ERR_get_error();
    return 1;
}
