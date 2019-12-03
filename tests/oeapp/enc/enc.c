// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "oeapp_t.h"

/* The 'oeapp policy' subcommand fills this in. */
OE_APP_SECTION oe_app_policy_t policy;

void hex_dump(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

void dump_string(const uint8_t* s, size_t n)
{
    printf("\"");

    for (size_t i = 0; i < n; i++)
    {
        int c = s[i];

        if (c >= ' ' && c <= '~')
            printf("%c", s[i]);
        else
            printf("\\%03o", s[i]);
    }

    printf("\"");
}

void dump_policy(oe_app_policy_t* policy)
{
    printf("policy =\n");
    printf("{\n");

    printf("    modulus=");
    hex_dump(policy->modulus, sizeof(policy->modulus));
    printf("\n");

    printf("    exponent=");
    hex_dump(policy->exponent, sizeof(policy->exponent));
    printf("\n");

    printf("    signer=");
    hex_dump(policy->signer, sizeof(policy->signer));
    printf("\n");

    printf("}\n");
}

void dump_policy_ecall(void)
{
    dump_policy(&policy);
}

void dump_signature(const oe_app_signature_t* signature)
{
    printf("signature =\n");
    printf("{\n");

    printf("    signer=");
    hex_dump(signature->signer, sizeof(signature->signer));
    printf("\n");

    printf("    hash=");
    hex_dump(signature->hash.buf, sizeof(signature->hash));
    printf("\n");

    printf("    signature=");
    hex_dump(signature->signature, sizeof(signature->signature));
    printf("\n");

    printf("}\n");
}

void verify_ecall(
    const struct _oe_app_signature* signature,
    const struct _oe_app_hash* hash)
{
    oe_result_t r;

    hex_dump(hash->buf, sizeof(oe_app_hash_t));

    /* Dump the structure. */
    dump_signature(signature);

    r = oe_app_verify_signature(signature, &policy, hash);
    OE_TEST(r == OE_OK);

    printf("=== VERIFY OKAY\n");
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
