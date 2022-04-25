#include <openenclave/enclave.h>

#include "dispatcher.h"
#include "safekeeper_t.h"
#include "shared.h"

static ecall_dispatcher dispatcher;

void generate_safekey() {
    dispatcher.prepare_safekey();
}

void seal_safekey(
    int sealPolicy,
    sealed_data_t* sealed_data
) {
   dispatcher.seal_safekey(sealPolicy, sealed_data); 
}

void hash_password(
    unsigned char* input,
    size_t input_size,
    unsigned char* salt,
    size_t salt_size,
    unsigned char* output
) {
    dispatcher.cmac_input(input, input_size, salt, salt_size, output);
}

void close_dispatcher() {
    dispatcher.close();
}
