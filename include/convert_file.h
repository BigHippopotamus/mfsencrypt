#ifndef _CONVERT_FILE_H
#define _CONVERT_FILE_H

#include <openssl/crypto.h>

int merge_files(char *infiles[],
                char *outfile,
                char *keys[],
                int count,
                int extra_padding,
                OSSL_LIB_CTX *lib_context);

int regenerate_file(char *infile,
                    char *outfile,
                    char *key,
                    OSSL_LIB_CTX *lib_context);

#endif