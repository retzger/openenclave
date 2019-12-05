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

void dump_policy_ecall(void)
{
    oe_app_dump_policy(&policy);
}

void verify_ecall(
    const struct _oe_app_sigstruct* sigstruct,
    const struct _oe_app_hash* apphash)
{
    oe_result_t r;

    oe_app_dump_hash("apphash", apphash);

    /* Dump the structure. */
    oe_app_dump_sigstruct(sigstruct);

    r = oe_app_verify_signature(
        &policy.pubkey, &policy.appid, apphash, &sigstruct->signature);
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
