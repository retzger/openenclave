// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <openenclave/host.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oeapp_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_app_sigstruct_t sigstruct;
    oe_app_hash_t hash;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH SIGFILE HASH\n", argv[0]);
        return 1;
    }

    /* Load the sigstruct file. */
    OE_TEST(oe_app_load_sigstruct(argv[2], &sigstruct) == 0);

    result = oe_create_oeapp_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = dump_policy_ecall(enclave);
    OE_TEST(result == OE_OK);

    OE_TEST(oe_app_ascii_to_hash(argv[3], &hash) == OE_OK);

    result = verify_ecall(enclave, &sigstruct, &hash);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (oeapp)\n");

    return 0;
}
