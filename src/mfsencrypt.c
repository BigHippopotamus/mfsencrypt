#include "convert_file.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

typedef enum Mode {
    NONE,
    ENCRYPT,
    DECRYPT,
    KEY,
    OUTPUT,
    PADDING
} Mode;

int main(int argc, char *argv[]) {
    int return_value = 0;

    while (!RAND_poll());

    OSSL_LIB_CTX *lib_context = NULL;

    Mode mode = ENCRYPT;
    Mode action = ENCRYPT;
    int count = 0;
    int keycount = 0;

    int infiles = -1;
    int keys = -1;
    int outfile = -1;
    int padding = 0;

    int success;

    bool valid = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if (count > 0 || mode != ENCRYPT) {
                break;
            } else {
                mode = DECRYPT;
                action = DECRYPT;
            }
        } else if (strcmp(argv[i], "-k") == 0) {
            if (count == 0 || (mode != ENCRYPT && mode != DECRYPT)) {
                break;
            } else {
                mode = KEY;
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            if (mode != KEY) {
                break;
            } else if (keycount < count) {
                fprintf(
                    stderr,
                    "%s: Cannot have fewer keys than files\n",
                    argv[0]
                );
                exit(EXIT_FAILURE);
            } else {
                mode = OUTPUT;
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            if (mode != OUTPUT) {
                break;
            } else if (action == DECRYPT) {
                fprintf(
                    stderr,
                    "%s: Cannot pad when decrypting\n",
                    argv[0]
                );
                exit(EXIT_FAILURE);
            } else if (outfile == -1) {
                fprintf(
                    stderr,
                    "%s: No output file given\n",
                    argv[0]
                );
                exit(EXIT_FAILURE);
            } else {
                valid = false;
                mode = PADDING;
            }
        } else {
            switch (mode) {
                case ENCRYPT: {
                    if (infiles == -1) infiles = i;
                    count++;
                }
                break;

                case DECRYPT: {
                    if (infiles == -1) infiles = i;
                    count++;
                    if (count > 1) {
                        fprintf(
                            stderr,
                            "%s: Cannot decrypt more than one file\n",
                            argv[0]
                        );
                        exit(EXIT_FAILURE);
                    }
                }
                break;

                case KEY: {
                    if (keys == -1) keys = i;
                    keycount++;
                    if (keycount > count) {
                        fprintf(
                            stderr,
                            "%s: Cannot have more keys than files\n",
                            argv[0]
                        );
                        exit(EXIT_FAILURE);
                    }
                }
                break;

                case OUTPUT: {
                    if (outfile == -1) outfile = i;
                    if (valid) {
                        fprintf(
                            stderr,
                            "%s: Too many arguments for OUTPUT\n",
                            argv[0]
                        );
                        exit(EXIT_FAILURE);
                    } else {
                        valid = true;
                    }
                }
                break;

                case PADDING: {
                    if (valid) {
                        fprintf(
                            stderr,
                            "%s: Too many arguments for PADDING\n",
                            argv[0]
                        );
                        exit(EXIT_FAILURE);
                    } else {
                        char *is_num;
                        long converted = strtol(argv[i], &is_num, 10);

                        if (*is_num != '\0') {
                            fprintf(
                                stderr,
                                "%s: Invalid value for PADDING\n",
                                argv[0]
                            );
                            exit(EXIT_FAILURE);
                        } else if (converted < 0) {
                            fprintf(
                                stderr,
                                "%s: Value of PADDING cannot be negative\n",
                                argv[0]
                            );
                            exit(EXIT_FAILURE);
                        } else if (converted > INT_MAX) {
                            fprintf(
                                stderr,
                                "%s: Value of PADDING too large\n",
                                argv[0]
                            );
                            exit(EXIT_FAILURE);
                        } else {
                            padding = (int) converted;
                            valid = true;
                        }
                    }
                }
                break;
            }
        }
    }

    if (count == 0 || !valid) {
        fprintf(
            valid ? stdout : stderr,
            "Usage:\n"
            "Encryption: %1$s FILES... -k KEYS... -o OUTPUT [-p PADDING]\n"
            "Decryption: %1$s -d FILE -k KEY -o OUTPUT\n",
            argv[0]
        ); 
        exit(EXIT_FAILURE);
    }

    lib_context = OSSL_LIB_CTX_new();
    if (!lib_context) goto handle_error;

    if (action == ENCRYPT) {
        success = merge_files(
            argv + infiles,
            argv[outfile],
            argv + keys,
            count,
            padding,
            lib_context
        );
        if (!success) goto handle_error;
    } else if (action == DECRYPT) {
        success = regenerate_file(
            argv[infiles],
            argv[outfile],
            argv[keys],
            lib_context
        );
        if (!success) goto handle_error;
    }

    goto cleanup;

handle_error:
    return_value = 1;

    unsigned long openssl_error = ERR_get_error();
    if (openssl_error != 0) {
        fprintf(
            stderr,
            "%s: Failed with OPENSSL error %lu\n",
            argv[0],
            openssl_error
        );
    } else if (errno != 0) {
        fprintf(
            stderr,
            "%s: %s\n",
            argv[0],
            strerror(errno)
        );
    } else {
        fprintf(
            stderr,
            "%s: Failed with unknown error",
            argv[0]
        );
    }

cleanup:
    OSSL_LIB_CTX_free(lib_context);

    return return_value;
}

