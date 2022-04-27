# OE-Safekeeper
Re-creating the Safekeeper project using Open-Enclave (https://github.com/SafeKeeper)

# Notes

## Cryptography

The OpenEnclave SDK comes with partial mbedTLS support. You can find the list of supported mbedTLS functions here: https://github.com/openenclave/openenclave/blob/master/docs/MbedtlsSupport.md.
All the crypto operations in this project were done using the SDK's included mbedTLS library.

## Application Structure

The '''host''' 

## Making

Enclave code is built first, then host. The EDL header file specifies trusted and untrusted functions. The oeedger8r tool generates boilerplate code on top of these function definitions to get a full list of cpp files that can be compiled. 

## Generating Safekey

This is done using mbedtls_entropy_init and mbedtls_drbg_init to get an entropy source and set up a re-seeding source respectively. It generates by default a 16 byte key (for a 256 bit CMAC function). 

## Sealing the Safekey

The host passes the following data structure to the enclave:

```cpp
struct _sealed_data_t {
    unsigned char signature[SIGNATURE_SIZE];
    unsigned char iv[IV_SIZE];
    size_t key_info_size;
    size_t encrypted_data_size;
    unsigned char encrypted_data[SEALED_SAFEKEY_SIZE];
} sealed_data_t;
```

So the enclave:
1. Recovers its sealing key according to the sealing policy (saves size of key to sealed_data->key_info_size). Recall: the sealing key can be recovered by the enclave at anytime, and doesn't need to be saved - in fact it needs to be kept hidden from the host
2. Generates a random 16-byte IV (saves it to sealed_data->iv)
3. Encrypts the safekey using an AES-256-CBC cipher (saves it to sealed_data->encrypted_data)
4. Generates a signature over the sealed_data, using the sealing key and an HMAC algorithm
