#ifndef _ARGS_H
#define _ARGS_H

#include <stddef.h>

// AES-128-CMAC for Hashing
#define SAFEKEY_SIZE 16
#define SEALED_SAFEKEY_SIZE 48

// Per-enclave Sealing or Per-Signer Sealing
#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

// Salt Map Information
#define INITIAL_ATTEMPTS 10
#define TIMEOUT 100

// AES-CBC Encryption
#define IV_SIZE 16
#define SIGNATURE_SIZE 32
#define BLOCK_SIZE 16
#define ENCRYPT true
#define DECRYPT false

// Errors shared by host and enclave
#define ERROR_SIGNATURE_VERIFY_FAIL 1
#define ERROR_OUT_OF_MEMORY 2
#define ERROR_GET_SEALKEY 3
#define ERROR_SIGN_SEALED_DATA_FAIL 4
#define ERROR_CIPER_ERROR 5
#define ERROR_UNSEALED_DATA_FAIL 6
#define ERROR_SEALED_DATA_FAIL 7
#define ERROR_INVALID_PARAMETER 8

typedef struct _sealed_data_t {
    unsigned char signature[SIGNATURE_SIZE];
    unsigned char iv[IV_SIZE];
    size_t key_info_size;
    size_t encrypted_data_size;
    unsigned char encrypted_data[SEALED_SAFEKEY_SIZE];
} sealed_data_t;

#endif /* _ARGS_H */