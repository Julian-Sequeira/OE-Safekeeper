#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

#include "dispatcher.h"
#include "trace.h"

int ecall_dispatcher::sign_sealed_data(
    sealed_data_t* sealed_data,
    unsigned char* key,
    unsigned int key_size,
    unsigned char* signature
) {
    int ret = 0;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);

    ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    if (ret) goto exit;

    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret) goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->iv,
        IV_SIZE
    );
    if (ret) goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->key_info_size,
        IV_SIZE
    );
    if (ret) goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->encrypted_data_size,
        IV_SIZE
    );
    if (ret) goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->encrypted_data,
        IV_SIZE
    );
    if (ret) goto exit;

    ret = mbedtls_md_hmac_finish(&ctz, signature);
exit:
    mbedtls_md_free(&ctx);
    return ret;
}