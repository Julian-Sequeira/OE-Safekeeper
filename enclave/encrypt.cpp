#include "dispatcher.h"
#include "trace.h"

#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>

/*
 * AES-CBC Encryption/Decryption
 * Using mbedtls_aes_crypt_cbc function
 * Need to supply our own IV
 * Need to pad input before calling function
*/
int ecall_dispatcher::encrypt_decrypt(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* key,
    unsigned int key_size,
    unsigned char* iv,
    unsigned char* output_data
) {
    int ret = 0;

    // Prepare the AES Context
    unsigned char local_iv[IV_SIZE];
    mbedtls_aes_context aescontext;
    mbedtls_aes_init(&aescontext);
    memcpy((void*)local_iv, (void*)iv, IV_SIZE);

    if (encrypt) {
        ret = mbedtls_aes_setkey_enc(&aescontext, key, key_size*8);
    } else {
        ret = mbedtls_aes_setkey_dec(&aescontext, key, key_size*8);
    }

    if (ret != 0) {
        TRACE_ENCLAVE("Mbedtls set key failed with %d", ret);
        goto exit;
    }

    // MbedTLS has input limits
    if (input_data_size > UINT32_MAX) {
        TRACE_ENCLAVE("Data is too large to fit into an unsigned int");
        ret = ERROR_INVALID_PARAMETER;
        goto exit;
    if (key_size > UINT32_MAX) {
        TRACE_ENCLAVE("Key is too large to fit into an unsigned int");
        ret = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    // Need to pad the input for CBC Mode (PKCS#5 Padding)
    // If data is not divisible by BLOCK_SIZE - pad it until it is
    // If data is divisible by BLOCK_SIZE, add an extra block
    // The padding data is the number of of bytes added, repeated
    size_t bytes_left;
    size_t padded_byte_count;
    unsigned char* padded_data;

    bytes_left = input_data_size % BLOCK_SIZE;
    if (bytes_left == 0) {
        padded_byte_count = BLOCK_SIZE;
    } else {
        padded_byte_count = BLOCK_SIZE - bytes_left;
    }

    if (padded_byte_count > UINT32_MAX) {
        TRACE_ENCLAVE("Padded byte count too large to fit into an int");
        goto exit;
    }

    // Add padded data
    padded_data = (unsigned char*) malloc(input_data_size + padded_byte_count);
    if (padded_data == NULL) {
        TRACE_ENCLAVE("Malloc failed");
        ret = ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    memset((void*)padded_data, 0, input_data_size + padded_byte_count);
    memcpy((void*)padded_data, (void*)input_data, input_data_size);
    memset(
        (void*)(padded_data + input_data_size),
        (int)padded_byte_count,
        padded_byte_count
    );

    input_data_size += padded_byte_count;
    input_data = padded_data;

    // Encrypt or decrypt here
    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        input_data_size,
        local_iv,
        input_data,
        output_data
    );

    if (ret != 0) {
        TRACE_ENCLAVE("Mbedtls crypt failed");
        ret = ERROR_CIPER_ERROR;
        goto exit;
    }

    TRACE_ENCLAVE("Successful encryption");
exit:
    mbedtls_aes_free(&aescontext);
    return ret;
}