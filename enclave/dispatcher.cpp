/// Standard C libraries
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <map>
#include <vector>

/// mbedTLS Libraries
#include <mbedtls/error.h>
#include <mbedtls/config.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

/// Open-Enclave
#include <openenclave/corelibc/stdlib.h>

/// Local Dependencies
#include "dispatcher.h"
#include "trace.h"

/* 
 * Static Dispatcher for code organization
 * Contains a single lock for resource gating 
*/
ecall_dispatcher::ecall_dispatcher() {
    pthread_spin_init(&m_lock, PTHREAD_PROCESS_SHARED);
}

/*
 * The map is used to control password guesses
 * Salt is the key - get INTIAL_ATTEMPTS guesses before triggering a timeout
 * This is to prevent the untrusted host from brute force guessing passwords in an online attack
*/
int ecall_dispatcher::update_map(
    unsigned char* salt
) {
    /// Access to map is gated by a spinlock
    pthread_spin_lock(&m_lock);

    // Add to the map if not found in map
    // Else decrement counter
    map<unsigned char*, uint32_t>:: iterator it = m_attempts.find(salt);
    if (it == m_attempts.end()) {
        m_attempts[salt] = INITIAL_ATTEMPTS;
    } else {
        if (it->second == 0) {
            TRACE_ENCLAVE("Too many attempts: timeout for %d seconds", TIMEOUT);
            sleep(TIMEOUT);
            it->second = INITIAL_ATTEMPTS;
        }
        it->second--;
    }

    // Release the spinlock to allow future accesses
    pthread_spin_unlock(&m_lock);
    TRACE_ENCLAVE("Updating the salt map was successful");
    return 0;
}

/*
 * CMAC passwords with the safekey (AES-128 CBC mode)
 * Using mbedtls_cipher_cmac function
*/
int ecall_dispatcher::cmac_input(
    unsigned char* input,
    size_t input_size,
    unsigned char* salt,
    size_t salt_size,
    unsigned char* output
) {
    // Check the salt map
    int ret = 0;
    ret = update_map(salt);
    if (ret != 0) goto exit;

    // CMAC Metadata
    const mbedtls_cipher_info_t* cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    if (cipher_info == NULL) {
        TRACE_ENCLAVE("Error getting AES-CBC info");
        ret = 1;
        goto exit;
    }

    /// CMAC Operation
    ret = mbedtls_cipher_cmac(
        cipher_info,
        (unsigned char*)m_safekey,
        SAFEKEY_SIZE * 8,
        unsigned char*) input,
        input_size,
        output
    );

    if (ret != 0) {
        TRACE_ENCLAVE("CMAC Operation failed: %d", ret);
        goto exit;
    }
exit:
    return ret;
}

/*
 * Seal the safekey using the enclave's sealing key
 * Using OpenEnclave's o_get_seal_key_by_policyv2 API
*/ 
int ecall_dispatcher::seal_safekey(
    int seal_policy,
    sealed_data_t* sealed_data
) {
    int ret = 0;

    // First get the seal key
    uint8_t* key_info = NULL;
    size_t key_info_size = 0;

    uint8_t* seal_key = NULL;
    size_t seal_key_size = 0;

    oe_result_t result;
    result = oe_get_seal_key_by_policy(
        (oe_seal_policy_t) seal_policy,
        &seal_key,
        &seal_key_size,
        &key_info,
        &key_info_size
    );

    if (result != OE_OK) {
        TRACE_ENCLAVE("Getting seal key failed with %d", result);
        ret = 1;
        goto exit;
    }

    // Prepare the encryption metadata
    // Prepare the IV
    unsigned char iv[IV_SIZE];
    memset((void*)iv, 0, IV_SIZE);
    ret = generate_iv(iv, IV_SIZE);
    if (ret != 0) {
        TRACE_ENCLAVE("Generating random IV failed with %d", ret);
        goto exit;
    }

    // Prepare the output buffer
    // 48 bytes of ciphertext - 16 (IV) + 16 (1 block) + 16 (PKCE Padding)
    unsigned char output_data[SEALED_SAFEKEY_SIZE];
    memset((void*)output_data, 0, SEALED_SAFEKEY_SIZE);

    // Encrypt the safekey with the sealing key
    ret = encrypt_decrypt(
        bool encrypt,
        unsigned char* input_data,
        unsigned int input_data_size,
        unsigned char* key,
        unsigned int key_size,
        unsigned char* iv,
        unsigned char* output_data
    );
    if (ret != 0) {
        TRACE_ENCLAVE("Encryption of safekey failed with %d", ret);
        goto exit;
    }

    // Populate the sealed data structure
    // with metadata needed for decryption
    memcpy((void*)sealed_data->iv, (void*)iv, IV_SIZE);
    memcpy((void*)sealed_data->encrypted_data, (void*)output_data, SAFEKEY_SIZE);

    sealed_data->key_info_size = key_info_size;
    sealed_data->encrypted_data_size = SEALED_SAFEKEY_SIZE;

    // Finally, sign the hash of this structure
    unsigned char signature[SIGNATURE_SIZE];
    ret = sign_sealed_data(
        sealed_data,
        (unsigned char*)seal_key,
        seal_key_size,
        signature
    );
    if (ret != 0) {
        TRACE_ENCLAVE("HMAC Signature failed with %d", ret);
        goto exit;
    }

    memcpy((void*)sealed_data->signature, signature, SIGNATURE_SIZE);
    TRACE_ENCLAVE("Successfully sealed safekey");
exit:
    return ret;
}

/* 
 * Generate a random Safekey
 * Default size 16 bytes or SAFEKEY_SIZE
*/
int ecall_dispatcher::prepare_safekey() {
    int ret = 0;
    memset((void*)m_safekey, 0, SAFEKEY_SIZE);
    ret = generate_key((unsigned char*)m_safekey, SAFEKEY_SIZE);
    if (ret != 0){
        TRACE_ENCLAVE("Enclave: generating safekey failed with %d", ret);
        goto exit;
    }
exit:
    return ret;
} 

/*
 * Close the dispatcher
*/
void ecall_dispatcher::close() {
    TRACE_ENCLAVE("Closing dispatcher");
}
