// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <stdio.h>

static void _dump_hex(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
}

void oe_app_dump_hash(const char* name, const oe_app_hash_t* hash)
{
    printf("%s=", name);
    _dump_hex(hash->buf, sizeof(oe_app_hash_t));
    printf("\n");
}

void oe_app_dump_policy(const oe_app_policy_t* policy)
{
    printf("# policy\n");

    printf("modulus=");
    _dump_hex(policy->pubkey.modulus, sizeof(policy->pubkey.modulus));
    printf("\n");

    printf("exponent=");
    _dump_hex(policy->pubkey.exponent, sizeof(policy->pubkey.exponent));
    printf("\n");

    printf("signer=");
    _dump_hex(policy->signer.buf, sizeof(policy->signer.buf));
    printf("\n");

    printf("appid=");
    _dump_hex(policy->appid.buf, sizeof(policy->appid));
    printf("\n");
}

void oe_app_dump_sigstruct(const oe_app_sigstruct_t* sigstruct)
{
    printf("# sigstruct\n");

    printf("signer=");
    _dump_hex(sigstruct->signer.buf, sizeof(sigstruct->signer));
    printf("\n");

    printf("appid=");
    _dump_hex(sigstruct->appid.buf, sizeof(sigstruct->appid));
    printf("\n");

    printf("apphash=");
    _dump_hex(sigstruct->apphash.buf, sizeof(sigstruct->apphash));
    printf("\n");

    printf("signature=");
    _dump_hex(sigstruct->signature.buf, sizeof(sigstruct->signature));
    printf("\n");
}
