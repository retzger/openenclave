// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <stdio.h>
#include <string.h>

oe_result_t oe_app_verify_signature(
    oe_app_pubkey_t* pubkey,
    const oe_app_hash_t* appid,
    const oe_app_hash_t* apphash,
    const oe_app_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_rsa_public_key_t rpk;
    bool rpk_initialized = false;
    oe_app_hash_t hash;

    /* Check the parameters. */
    if (!signature || !pubkey || !appid || !apphash)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the composite hash of the appid and apphash. */
    {
        oe_sha256_context_t context;
        OE_SHA256 sha256;

        oe_sha256_init(&context);
        oe_sha256_update(&context, appid->buf, sizeof(*appid));
        oe_sha256_update(&context, apphash->buf, sizeof(*apphash));
        oe_sha256_final(&context, &sha256);

        memcpy(hash.buf, sha256.buf, sizeof(hash));
    }

    /* Initialize the RSA key from the policy. */
    OE_CHECK(oe_rsa_public_key_init_from_binary(
        &rpk,
        pubkey->modulus,
        sizeof(pubkey->modulus),
        pubkey->exponent,
        sizeof(pubkey->exponent)));
    rpk_initialized = true;

    /* Verify the signature of the hash. */
    OE_CHECK(oe_rsa_public_key_verify(
        &rpk,
        OE_HASH_TYPE_SHA256,
        hash.buf,
        sizeof(hash),
        signature->buf,
        sizeof(signature->buf)));

    result = OE_OK;

done:

    if (rpk_initialized)
        oe_rsa_public_key_free(&rpk);

    return result;
}
