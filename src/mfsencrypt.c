#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#include "tester.c"

int main() {
    while (!RAND_poll());

    OSSL_LIB_CTX *lib_context;
    lib_context = OSSL_LIB_CTX_new();

    if (!lib_context) goto handle_error;

/*
    test_field_reposition(lib_context);
    test_eval_function(lib_context);
    test_build_generator(lib_context);
    test_encode_decode(lib_context);
*/

    test_merge_files(lib_context);
    test_regenerate_file(lib_context, 0);

    OSSL_LIB_CTX_free(lib_context);

    return 0;

handle_error:
    OSSL_LIB_CTX_free(lib_context);

    return ERR_get_error();
    //return 1;
}
