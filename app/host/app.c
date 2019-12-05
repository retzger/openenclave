// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

oe_result_t oe_app_load_sigstruct(
    const char* path,
    oe_app_sigstruct_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    void* data = NULL;
    size_t size;

    OE_CHECK(__oe_load_file(path, 0, &data, &size));

    if (size != sizeof(oe_app_sigstruct_t))
        OE_RAISE(OE_FAILURE);

    memcpy(signature, data, sizeof(oe_app_sigstruct_t));

    result = OE_OK;

done:

    if (data)
        free(data);

    return result;
}

oe_result_t oe_app_ascii_to_hash(const char* ascii, oe_app_hash_t* hash)
{
    oe_result_t result = OE_UNEXPECTED;
    const char* p = ascii;

    memset(hash, 0, OE_APP_HASH_SIZE);

    if (strlen(ascii) != 2 * OE_APP_HASH_SIZE)
        OE_RAISE(OE_FAILURE);

    for (size_t i = 0; i < OE_APP_HASH_SIZE; i++)
    {
        unsigned int byte;
        int n;

        n = sscanf(p, "%02x", &byte);

        if (n != 1)
            OE_RAISE(OE_FAILURE);

        hash->buf[i] = (uint8_t)byte;
        p += 2;
    }

    result = OE_OK;

done:
    return result;
}
