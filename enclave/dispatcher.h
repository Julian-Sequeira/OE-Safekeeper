#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <openenclave/corelibc/stdlib.h>

#include <string>
#include <map>

#include "shared.h"
#include "safekeeper_args.h"

using namespace std;

class ecall_dispatcher {

    public:
        ecall_dispatcher();
        void close();
        
        int prepare_safekey();
        int seal_safekey(
            int seal_policy,
            sealed_data_t* sealed_data
        );       
        int cmac_input(
            unsigned char* input,
            size_t input_size,
            unsigned char* salt,
            size_t salt_size,
            unsigned char* output
        );
    
    private:
        unsigned char m_safekey[SAFEKEY_SIZE];
        map<unsigned char*, unsigned int> m_attempts;
        pthread_spinlock_t m_lock;

        int generate_key(
            unsigned char* key,
            unsigned int key_size
        );

        int generate_iv(
            unsigned char* iv,
            unsigned int ivSize
        );

        int update_map(
            unsigned char* salt
        );

        int encrypt_decrypt(
            bool encrypt,
            unsigned char* input_data,
            unsigned int input_data_size,
            unsigned char* key,
            unsigned int key_size,
            unsigned char* iv,
            unsigned char* output_data 
        );

        int sign_sealed_data(
            sealed_data_t* sealed_data,
            unsigned char* key,
            unsigned int key_size,
            unsigned char* signature
        );
}