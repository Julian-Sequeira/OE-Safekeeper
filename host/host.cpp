#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <limits.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openenclave/host.h>

#include "safekeeper_u.h"
#include "../shared.h"

using namespace std;

oe_enclave_t* enclave;
#define GET_POLICY_NAME(policy) \
    ((policy == POLICY_UNIQUE) ? "POLICY_UNIQUE" : "POLICY_PRODUCT")

int main(int argc, const char* argv[]) {

    if (argc != 2) {
        cerr << "Usage: " << argv[0] << "ENCLAVE_PATH.signed" << endl;
        ret = 1;
        goto exit;
    }

    int ret = 0;
    oe_result_t result;
    result = oe_create_safekeeper_enclave(
        arv[1],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVe_FLAG_DEBUG,
        NULL,
        0,
        &enclave
    );

    if (result != OE_OK) {
        cerr << "Host: oe_create_safekeeper_enclave() failed with " << argv[0] << " " << result << endl;
        ret = 1;
        goto exit;
    }

    // Make the safekey
    result = generate_safekey(enclave);
    if (result != OE_OK) {
        cerr << "Host: gen_safekey() failed with " << argv[0] << " " << result << endl;
        ret = 1;
        goto exit;
    }

    // Hash a password input
    const char* test_input = "iloveyou";
    size_t input_size = 8;
    const char* test_salt = "16characters1616";
    size_t salt_size = 16;
    unsigned char output[128];

    result = hash_password(
        enclave,
        (unsigned char*)test_input,
        input_size,
        (unsigned char*)test_salt,
        salt_size,
        output
    );

    if (result != OE_OK) cerr << "Host: hash_password() failed with " << result << endl;

    // Seal the safekey
    sealed_data_t sealed_data;
    result = seal_safekey(
        enclave,
        POLICY_UNIQUE,
        &sealed_data
    );
    if (result != OE_OK) cerr << "Host: seal_safekey() failed with " << result << endl;

exit:
    cout << "Host: terminating the enclave" << endl;
    oe_terminate_enclave(enclave);
    return ret;
}
