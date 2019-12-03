// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_APP_H
#define _OE_BITS_APP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#define OE_APP_SECTION __attribute__((section(".oeapp")))

#define OE_APP_HASH_SIZE 32

#define OE_APP_KEY_SIZE 384

#define OE_APP_EXPONENT_SIZE 4

#define OE_APP_SIGNATURE_SIZE 32

/* Represents a SHA-256 hash */
typedef struct _oe_app_hash
{
    uint8_t buf[OE_APP_HASH_SIZE];
} oe_app_hash_t;

/* A policy injected by 'oeapp append' tool. */
typedef struct _oe_app_policy
{
    /* The modulus of the signer's public key. */
    uint8_t modulus[OE_APP_KEY_SIZE];

    /* The exponent of the signer's public key. */
    uint8_t exponent[OE_APP_EXPONENT_SIZE];

    /* The signer's ID (the SHA-256 public signing key) */
    uint8_t signer[OE_APP_HASH_SIZE];
} oe_app_policy_t;

/* An signature injected by oesignapp tool. */
typedef struct _oe_app_signature
{
    /* The signer's ID (the SHA-256 of the public signing key). */
    uint8_t signer[OE_APP_SIGNATURE_SIZE];

    /* The hash of the appension. */
    oe_app_hash_t hash;

    /* The signature of SHA-256(hash | isvprodid | isvsvn). */
    uint8_t signature[OE_APP_KEY_SIZE];
} oe_app_signature_t;

oe_result_t oe_app_verify_signature(
    const oe_app_signature_t* signature,
    const oe_app_policy_t* policy,
    const oe_app_hash_t* hash);

#endif /* _OE_BITS_APP_H */
