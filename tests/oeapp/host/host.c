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

int _load_signature_file(const char* path, oe_app_signature_t* signature)
{
    int ret = -1;
    void* data = NULL;
    size_t size;

    if (__oe_load_file(path, 0, &data, &size) != 0)
        goto done;

    if (size != sizeof(oe_app_signature_t))
        goto done;

    memcpy(signature, data, sizeof(oe_app_signature_t));

    ret = 0;

done:

    if (data)
        free(data);

    return ret;
}

int _ascii_to_hash(const char* ascii_hash, oe_app_hash_t* hash)
{
    const char* p = ascii_hash;

    memset(hash, 0, OE_APP_HASH_SIZE);

    if (strlen(ascii_hash) != 2 * OE_APP_HASH_SIZE)
        return -1;

    for (size_t i = 0; i < OE_APP_HASH_SIZE; i++)
    {
        unsigned int byte;
        int n;

        n = sscanf(p, "%02x", &byte);

        if (n != 1)
            return -1;

        hash->buf[i] = (uint8_t)byte;
        p += 2;
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_app_signature_t signature;
    oe_app_hash_t hash;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH SIGFILE HASH\n", argv[0]);
        return 1;
    }

    /* Load the signature file. */
    OE_TEST(_load_signature_file(argv[2], &signature) == 0);

    result = oe_create_oeapp_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = dump_policy_ecall(enclave);
    OE_TEST(result == OE_OK);

    OE_TEST(_ascii_to_hash(argv[3], &hash) == 0);

    result = verify_ecall(enclave, &signature, &hash);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (oeapp)\n");

    return 0;
}
