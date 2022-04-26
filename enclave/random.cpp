#include "trace.h"
#include "dispatcher.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

using namespace std;

int ecall_dispatcher::generate_key(
    unsigned char* key,
    unsigned int key_size
) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char pers[] = "EncryptionKey";
    int ret = 0;

    TRACE_ENCLAVE("Generating safekey");
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(key, 0, key_size);

    // Mbedtls_ctr_drbg_seed seeds and sets up 
    // the CTR_DRBG entropy source for future reseeds
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (unsigned char*)pers,
        sizeof(pers)
    );

    if (ret != 0) {
        TRACE_ENCLAVE("Failed to set up entropy source");
        goto exit;
    }
    TRACE_ENCLAVE("Safekey successfully generated");
exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int ecall_dispatcher::generate_iv(
    unsigned char* iv,
    unsigned int ivSize
) {
    memset(iv, 0, ivSize);
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char pers[] = "Random IV";
    int ret = 0;

    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (unsigned char*)pers,
        sizeof(pers)
    );

    if (ret != 0) {
        TRACE_ENCLAVE("Failed to set up entropy source");
        goto exit;
    }
    TRACE_ENCLAVE("IV successfully generated");
exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}