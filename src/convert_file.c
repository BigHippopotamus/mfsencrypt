#include "convert_file.h"
#include "encode_decode.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define FIELD_MOD "62b550139847676de987d98f9cc32c73d38f1a7969285cb18acb9689fb824bb75"
#define VALUE_MOD "10000000000000000"  // 2^64

#define BLOCK_SIZE 8
#define HASH_SIZE 32
#define FIELD_SIZE_BYTES 260

#define RAND_STRENGTH 256

void calculate_lps(unsigned char *pattern, int size, unsigned int *lps) {
    lps[0] = 0;

    int i = 1, prefix_size = 0;
    while (i < size) {
        if (pattern[i] == pattern[prefix_size]) {
            prefix_size++;
            lps[i] = prefix_size;
            i++;
        } else {
            if (prefix_size > 0) {
                prefix_size = lps[prefix_size - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

int stream_kmp(unsigned char *needle,
               unsigned int lps[],
               int needle_size,
               unsigned char *haystack,
               int haystack_size,
               int *progress) {
    for (int i = 0; i < haystack_size; i++) {
        while (*progress > 0 && needle[*progress] != haystack[i]) {
            *progress = lps[*progress - 1];
        }

        if (needle[*progress] == haystack[i]) {
            (*progress)++;
        }

        if (*progress == needle_size) {
            return i + 1;
        }
    }

    return 0;
}

int merge_files(char *infiles[],
                char *outfile,
                char *keys[],
                int real_count,
                int extra_padding,
                int fake_count,
                OSSL_LIB_CTX *lib_context) {
    int return_value = 1;
    int count = real_count + fake_count;

    FILE **inputs = NULL;
    FILE *output = NULL;
    off_t *filesizes = NULL;
    int max_size = 0;
    unsigned char bignum_bytes_buffer[FIELD_SIZE_BYTES];

    BN_CTX *context = NULL;
    BIGNUM **x = NULL;
    BIGNUM **y = NULL;
    BIGNUM **generator = NULL;
    BIGNUM *field_mod = NULL, *value_mod = NULL;

    uint64_t *padding = NULL;

    unsigned char (*key_hash)[HASH_SIZE] = NULL;
    unsigned int (*kmp_lps)[HASH_SIZE] = NULL;
    unsigned char sha_temp[HASH_SIZE];

    int *kmp_match_status = NULL;
    int *hash_used = NULL;

    unsigned char bytes[BLOCK_SIZE] = {0};

    int success;

    inputs = calloc(real_count, sizeof(*inputs));
    if (!inputs) goto handle_error;

    filesizes = calloc(real_count, sizeof(*filesizes));
    if (!inputs) goto handle_error;

    // Initialize BIGNUMs
    x = OPENSSL_zalloc(count * sizeof(*x));
    if (!x) goto handle_error;
    
    y = OPENSSL_zalloc(count * sizeof(*y));
    if (!y) goto handle_error;

    generator = OPENSSL_zalloc(count * sizeof(*generator));
    if (!generator) goto handle_error;

    for (int i = 0; i < count; i++) {
        x[i] = BN_new();
        if (!x[i]) goto handle_error;

        y[i] = BN_new();
        if (!y[i]) goto handle_error;

        generator[i] = BN_new();
        if (!generator[i]) goto handle_error;
    }

    success = BN_hex2bn(&field_mod, FIELD_MOD);
    if (!success) goto handle_error;

    success = BN_hex2bn(&value_mod, VALUE_MOD);
    if (!success) goto handle_error;

    // Calculate the size of each file
    for (int i = 0; i < real_count; i++) {
        inputs[i] = fopen(infiles[i], "rb");
        if (!inputs[i]) goto handle_error;

        fseeko(inputs[i], 0, SEEK_END);
        filesizes[i] = ftello(inputs[i]);
        rewind(inputs[i]);

        if (filesizes[i] > max_size) 
            max_size = filesizes[i];
    }

    // Calculate the number of bytes of padding needed for each file
    padding = calloc(real_count, sizeof(*padding));
    if (!padding) goto handle_error;

    uint64_t required_padding = extra_padding * BLOCK_SIZE + HASH_SIZE +
        (BLOCK_SIZE - max_size % BLOCK_SIZE) % BLOCK_SIZE;
    for (int i = 0; i < real_count; i++) {
        padding[i] = (max_size - filesizes[i]) + required_padding;
    }

    // Calculate hashes of the keys
    key_hash = calloc(real_count, sizeof(*key_hash));
    if (!key_hash) goto handle_error;

    kmp_lps = calloc(real_count, sizeof(*kmp_lps));
    if (!kmp_lps) goto handle_error;

    for (int i = 0; i < real_count; i++) {
        // Padding hash
        success = EVP_Digest(
            keys[i],
            strlen(keys[i]),
            key_hash[i],
            NULL,
            EVP_sha512_256(),
            NULL
        );
        if (!success) goto handle_error;

        calculate_lps(key_hash[i], HASH_SIZE, kmp_lps[i]);

        // x value hash
        success = EVP_Digest(
            keys[i],
            strlen(keys[i]),
            sha_temp,
            NULL,
            EVP_sha256(),
            NULL
        );
        if (!success) goto handle_error;

        success = (BN_bin2bn(
            sha_temp,
            HASH_SIZE,
            x[i]
        ) != NULL);
        if (!success) goto handle_error;
    }

    context = BN_CTX_new_ex(lib_context);
    if (!context) goto handle_error;

    for (int i = real_count; i < count; i++) {
        success = BN_rand_range_ex(
            x[i],
            field_mod,
            RAND_STRENGTH,
            context
        );

        // Check if it is a duplicate
        bool is_duplicate = false;
        for (int j = 0; j < i; j++) {
            int cmp = BN_cmp(x[i], x[j]);
            if (cmp == 0) {
                is_duplicate = true;
                break;
            }
        }

        if (is_duplicate) {
            i--;
            continue;
        }
    }

    // Generate the output
    uint64_t blocks = (filesizes[0] + padding[0]) / BLOCK_SIZE;
    output = fopen(outfile, "wb");

    uint64_t header[] = {count, blocks};
    int header_len = 2;

    success = 
        (fwrite(header, sizeof(header[0]), header_len, output) == header_len);
    if (!success) goto handle_error;

    kmp_match_status = calloc(real_count, sizeof(*kmp_match_status));
    hash_used = calloc(real_count, sizeof(*hash_used));
    for (uint64_t i = 0; i < blocks; i++) {
        // Generate data/padding to be used
        for (int j = 0; j < real_count; j++) {
            int old_status = kmp_match_status[j];
            unsigned int rand_bytes, hash_bytes, data_bytes;

            if (padding[j] >= HASH_SIZE + BLOCK_SIZE) {
                rand_bytes = BLOCK_SIZE;
                hash_bytes = 0;
                data_bytes = 0;
            } else if (padding[j] > HASH_SIZE) {
                rand_bytes = padding[j] - HASH_SIZE;
                hash_bytes = BLOCK_SIZE - rand_bytes;
                data_bytes = 0;
            } else if (padding[j] > BLOCK_SIZE) {
                rand_bytes = 0;
                hash_bytes = BLOCK_SIZE;
                data_bytes = 0;
            } else if (padding[j] > 0) {
                rand_bytes = 0;
                hash_bytes = padding[j];
                data_bytes = BLOCK_SIZE - hash_bytes;
            } else {
                rand_bytes = 0;
                hash_bytes = 0;
                data_bytes = BLOCK_SIZE;
            }
            int check_hash_in_rand = rand_bytes > 0;

            int used_bytes = 0;
            if (rand_bytes > 0) {
                success = RAND_bytes_ex(
                    lib_context,
                    bytes,
                    rand_bytes,
                    RAND_STRENGTH
                );
                if (!success) goto handle_error;

                used_bytes += rand_bytes;
            }

            if (hash_bytes > 0) {
                memcpy(
                    bytes + used_bytes,
                    key_hash[j] + hash_used[j],
                    hash_bytes
                );

                used_bytes += hash_bytes;
            }

            if (data_bytes > 0) {
                success = (fread(
                    bytes + used_bytes,
                    sizeof(bytes[0]),
                    data_bytes,
                    inputs[j]
                ) == data_bytes);
                if (!success) goto handle_error;

                used_bytes += data_bytes;
            }

            // Ensure random bytes are not hash
            if (check_hash_in_rand) {
                int hash_in_rand = stream_kmp(
                    key_hash[j],
                    kmp_lps[j],
                    HASH_SIZE,
                    bytes,
                    BLOCK_SIZE,
                    &kmp_match_status[j]
                );

                if (hash_in_rand) {
                    j--;
                    continue;
                }
            }

            hash_used[j] += hash_bytes;
            padding[j] -= rand_bytes + hash_bytes;
            filesizes[j] -= data_bytes;

            success = (BN_bin2bn(
                bytes,
                BLOCK_SIZE,
                y[j]
            ) != NULL);
            if (!success) goto handle_error;
        }

        for (int j = real_count; j < count; j++) {
            int rand_bytes = BLOCK_SIZE;

            success = RAND_bytes_ex(
                lib_context,
                bytes,
                BLOCK_SIZE,
                RAND_STRENGTH
            );
            if (!success) goto handle_error;

            success = (BN_bin2bn(
                bytes,
                BLOCK_SIZE,
                y[j]
            ) != NULL);
            if (!success) goto handle_error;
        }
        
        success = encode_block(
            generator,
            x,
            y,
            count,
            field_mod,
            value_mod,
            lib_context
        );
        if (!success) goto handle_error;

        // Write generator to file
        for (int j = 0; j < count; j++) {
            int8_t coeff_size = BN_num_bytes(generator[j]);
            if (BN_is_negative(generator[j])) coeff_size *= -1;
            success = (fwrite(&coeff_size, sizeof(coeff_size), 1, output) == 1);
            if (!success) goto handle_error;

            success = BN_bn2binpad(
                generator[j],
                bignum_bytes_buffer,
                abs(coeff_size)
            );
            if (!success) goto handle_error;

            success = (fwrite(
                bignum_bytes_buffer,
                sizeof(bignum_bytes_buffer[0]),
                abs(coeff_size),
                output
            ) == abs(coeff_size));
            if (!success) goto handle_error;
        }
    }

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    free(kmp_match_status);
    free(hash_used);

    free(key_hash);
    free(kmp_lps);

    free(padding);

    BN_CTX_free(context);

    for (int i = 0; i < real_count; i++) {
        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(generator[i]);
        if (inputs[i]) fclose(inputs[i]);
    }

    for (int i = real_count; i < count; i++) {
        BN_free(x[i]);
        BN_free(y[i]);
        BN_free(generator[i]);
    }

    if (output) fclose(output);

    BN_free(field_mod);
    BN_free(value_mod);

    OPENSSL_free(x);
    OPENSSL_free(y);
    OPENSSL_free(generator);

    free(filesizes);
    free(inputs);

    return return_value;
}

int regenerate_file(char *infile,
                    char *outfile,
                    char *key,
                    OSSL_LIB_CTX *lib_context) {
    int return_value = 1;

    FILE *input = NULL;
    FILE *output = NULL;
    unsigned char bignum_bytes_buffer[FIELD_SIZE_BYTES];

    uint64_t count = 0, blocks;

    BIGNUM *x = NULL, *y = NULL;
    BIGNUM **generator = NULL;
    BIGNUM *field_mod = NULL, *value_mod = NULL;

    int success;

    input = fopen(infile, "rb");
    if (!input) goto handle_error;

    output = fopen(outfile, "wb");
    if (!output) goto handle_error;

    // Initialize moduli
    success = BN_hex2bn(&field_mod, FIELD_MOD);
    if (!success) goto handle_error;

    success = BN_hex2bn(&value_mod, VALUE_MOD);
    if (!success) goto handle_error;

    success = (fread(
        &count,
        sizeof(count),
        1,
        input
    ) == 1);
    if (!success) goto handle_error;

    success = (fread(
        &blocks,
        sizeof(blocks),
        1,
        input
    ) == 1);
    if (!success) goto handle_error;

    generator = OPENSSL_zalloc(count * sizeof(*generator));
    if (!generator) goto handle_error;

    for (int i = 0; i < count; i++) {
        generator[i] = BN_new();
        if (!generator[i]) goto handle_error;
    }
    
    x = BN_new();
    if (!x) goto handle_error;

    y = BN_new();
    if (!y) goto handle_error;

    unsigned char key_hash[HASH_SIZE];
    unsigned int kmp_lps[HASH_SIZE];
    unsigned char sha_temp[HASH_SIZE];

    // Calculate hashes
    // Padding hash
    success = EVP_Digest(
        key,
        strlen(key),
        key_hash,
        NULL,
        EVP_sha512_256(),
        NULL
    );
    if (!success) goto handle_error;

    calculate_lps(key_hash, HASH_SIZE, kmp_lps);

    // x value hash
    success = EVP_Digest(
        key,
        strlen(key),
        sha_temp,
        NULL,
        EVP_sha256(),
        NULL
    );
    if (!success) goto handle_error;

    success = (BN_bin2bn(
        sha_temp,
        HASH_SIZE,
        x
    ) != NULL);
    if (!success) goto handle_error;

    int padding_over = 0;
    unsigned char bytes[BLOCK_SIZE];
    int kmp_match_status = 0;
    for (int i = 0; i < blocks; i++) {
        for (int j = 0; j < count; j++) {
            int8_t coeff_size;
            success = (fread(
                &coeff_size,
                sizeof(coeff_size),
                1,
                input
            ) == 1);
            if (!success) goto handle_error;

            success = (fread(
                bignum_bytes_buffer,
                sizeof(bignum_bytes_buffer[0]),
                abs(coeff_size),
                input
            ) == abs(coeff_size));
            if (!success) goto handle_error;

            success = (BN_bin2bn(
                bignum_bytes_buffer,
                abs(coeff_size),
                generator[j]
            ) != NULL);
            if (!success) goto handle_error;

            BN_set_negative(generator[j], coeff_size < 0);
        }

        success = decode_block(
            y,
            generator,
            x,
            count,
            field_mod,
            value_mod,
            lib_context
        );
        if (!success) goto handle_error;

        success = BN_bn2binpad(y, bytes, BLOCK_SIZE);
        if (!success) goto handle_error;

        // Only print to file if padding is over
        //*
        if (!padding_over) {
            int hash_location = stream_kmp(
                key_hash,
                kmp_lps,
                HASH_SIZE,
                bytes,
                BLOCK_SIZE,
                &kmp_match_status
            );

            if (hash_location) {
                padding_over = true;

                int valuable_bytes = BLOCK_SIZE - hash_location;
                success = (fwrite(
                    bytes + hash_location,
                    sizeof(bytes[0]),
                    valuable_bytes,
                    output
                ) == valuable_bytes);
                if (!success) goto handle_error;
            }
        } else {
            success = (fwrite(
                bytes,
                sizeof(bytes[0]),
                BLOCK_SIZE,
                output
            ) == BLOCK_SIZE);
            if (!success) goto handle_error;
        }
    }

    goto cleanup;

handle_error:
    return_value = 0;

cleanup:
    if (input) fclose(input);
    if (output) fclose(output);

    for (int i = 0; i < count; i++) {
        BN_free(generator[i]);
    }
    OPENSSL_free(generator);

    BN_free(x);
    BN_free(y);

    BN_free(field_mod);
    BN_free(value_mod);

    return return_value;
}
