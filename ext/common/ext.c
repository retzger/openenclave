// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/ext.h>
#include <stdio.h>

static void _dump_hex(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
}

static void _dump_string(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        uint8_t c = data[i];

        switch (c)
        {
            case '\r':
                printf("\\r");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\t':
                printf("\\t");
                break;
            case '\f':
                printf("\\f");
                break;
            default:
            {
                if (c >= ' ' && c <= '~')
                {
                    printf("%c", c);
                }
                else
                {
                    printf("\\%03o", c);
                }
                break;
            }
        }
    }
}

void oe_ext_dump_hash(const char* name, const oe_ext_hash_t* hash)
{
    printf("# hash\n");
    printf("%s=", name);
    _dump_hex(hash->buf, sizeof(oe_ext_hash_t));
    printf("\n");
    printf("\n");
}

void oe_ext_dump_policy(const oe_ext_policy_t* policy)
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

    printf("extid=");
    _dump_hex(policy->extid.buf, sizeof(policy->extid));
    printf("\n");

    printf("payload=");
    _dump_string(policy->payload, policy->payload_size);
    printf("\n");

    printf("payload_size=%zu\n", policy->payload_size);

    printf("\n");
}

void oe_ext_dump_sigstruct(const oe_ext_sigstruct_t* sigstruct)
{
    printf("# sigstruct\n");

    printf("signer=");
    _dump_hex(sigstruct->signer.buf, sizeof(sigstruct->signer));
    printf("\n");

    printf("extid=");
    _dump_hex(sigstruct->extid.buf, sizeof(sigstruct->extid));
    printf("\n");

    printf("exthash=");
    _dump_hex(sigstruct->exthash.buf, sizeof(sigstruct->exthash));
    printf("\n");

    printf("signature=");
    _dump_hex(sigstruct->signature.buf, sizeof(sigstruct->signature));
    printf("\n");

    printf("\n");
}
