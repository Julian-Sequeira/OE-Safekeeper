# OE-Safekeeper
Re-creating the Safekeeper project using Open-Enclave (https://github.com/SafeKeeper)

# Cryptography

The OpenEnclave SDK comes with partial mbedTLS support. You can find the list of supported mbedTLS functions here: https://github.com/openenclave/openenclave/blob/master/docs/MbedtlsSupport.md.
All the crypto operations in this project were done using the SDK's included mbedTLS library.

## Random

This is done using ```mbedtls_entropy_init``` and ```mbedtls_drbg_init``` to get an entropy source and set up a re-seeding source respectively.

## Encryption

Encryption was done using an AES-128-CBC cipher. This required generating a random IV, PKCS5 padding the plaintext data so it was a multiple of 128 bits, setting the encryption key with ```mbedtls_set_key_enc```, then using ```mbedtls_aes_crypt_cbc``` to perform the operation.

## CMAC

Also done using an AES-128-CBC cipher, using the ```mbedtls_cipher_cmac``` function.

# Application Structure

Recall: SGX applications are divided into trusted and untrusted components. The untrusted component can do I/O (in this case, it is meant to interface with a web server), and the trusted can handle secrets. Trusted functionality is kept inside ```/enclave``` and untrusted inside ```/host```. 

## Making

Enclave code is built first, then host. The safekeeper.edl header file specifies trusted and untrusted functions. The oeedger8r tool generates boilerplate code on top of these function definitions to get a full list of cpp files that can be compiled. So in addition to ```host/host.cpp``` and ```enclave/ecalls.cpp```, you have:
- host/safekeeper_u.c
- host/safekeeper_u.h
- enclave/safekeeper_args.c
- enclave/safekeeper_args.h
- enclave/safekeeper_t.c
- enclave/safekeeper_t.h

You end up with two binaries: ```safekeeperhost``` as the untrusted segment, and ```safekeeperenc``` as the untrusted component. You can include struct definitions in the EDL file if necessary, but then you need to include 'enclave/safekeeper_args.h' in your class files.

## Signing

The trusted binary needs to be signed in order to be launched by SGX. The Makefiles do this automatically here - generating a public/private key pair, and signing to create ```safekeeperenc.signed```. 

# Safekey
## Generation

 It generates by default a 16 byte key (for a 256 bit CMAC function). 

## Sealing

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
4. Generates an HMAC signature over the sealed_data using the sealing key

Then the enclave passes ```sealed_data``` back to the host.

# Controlling Guesses

This was done using a salt map and a ```pthread_spinlock_t``` primitive. Open-Enclave supports some libc functions, including ```phtread.h```: https://github.com/openenclave/openenclave/blob/master/docs/LibcSupport.md.

The spinlock gates access to the salt map. The salt map is a map of salts to counters representing attempts on that salt. Its default starting value is 10 attempts - once the counter reaches zero, it waits 10 seconds (default value), before resetting the counter to its starting value. Time might be controlled by the untrusted system, allowing the host system to break this reset functionality, this is a potential weakness of the application that should be addressed (open-enclave does not appear to support SGX trusted time). 
