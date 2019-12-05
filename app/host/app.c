// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/bits/app.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

oe_result_t _ascii_to_binary(const char* ascii, uint8_t* data, size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    const char* p = ascii;

    if (!ascii || !data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(data, 0, size);

    if (strlen(ascii) != 2 * size)
        OE_RAISE(OE_FAILURE);

    for (size_t i = 0; i < size; i++)
    {
        unsigned int byte;
        int n;

        n = sscanf(p, "%02x", &byte);

        if (n != 1)
            OE_RAISE(OE_FAILURE);

        data[i] = (uint8_t)byte;
        p += 2;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_app_ascii_to_hash(const char* ascii, oe_app_hash_t* hash)
{
    return _ascii_to_binary(ascii, hash->buf, sizeof(oe_app_hash_t));
}

#if 0
oe_result_t oe_app_load_sigstruct(
    const char* path,
    oe_app_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    void* data = NULL;
    size_t size;

    if (!path || !sigstruct)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(__oe_load_file(path, 0, &data, &size));

    if (size != sizeof(oe_app_sigstruct_t))
        OE_RAISE(OE_FAILURE);

    memcpy(sigstruct, data, sizeof(oe_app_sigstruct_t));

    result = OE_OK;

done:

    if (data)
        free(data);

    return result;
}
#endif

oe_result_t oe_app_load_sigstruct(
    const char* path,
    oe_app_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    FILE* is = NULL;
    char line[4096];

    if (sigstruct)
        memset(sigstruct, 0, sizeof(oe_app_sigstruct_t));

    if (!path || !sigstruct)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(is = fopen(path, "r")))
        OE_RAISE(OE_NOT_FOUND);

    while (fgets(line, sizeof(line), is) != NULL)
    {
        size_t len = strlen(line);
        char* p = line;
        char* end = p + len;
        const char* name;
        char* name_end;

        if (len == sizeof(line) - 1)
            OE_RAISE(OE_FAILURE);

        /* Remove leading whitespace */
        while (isspace(*p))
            p++;

        /* Remove trailing whitespace */
        while (end != p && isspace(end[-1]))
            *--end = '\0';

        /* Skip comment lines and empty */
        if (p[0] == '#' || p[0] == '\0')
            continue;

        /* Read the name */
        {
            const char* start = p;

            if (!(isalpha(*p) || *p == '_'))
                OE_RAISE(OE_FAILURE);

            p++;

            while (isalnum(*p) || *p == '_')
                p++;

            name = start;
            name_end = p;
        }

        /* Expect equal */
        {
            /* Skip whitespace. */
            while (isspace(*p))
                p++;

            /* Expect '=' characer */
            if (*p++ != '=')
                OE_RAISE(OE_FAILURE);

            /* Skip whitespace. */
            while (isspace(*p))
                p++;
        }

        /* Null-terminate the name now */
        *name_end = '\0';

        /* Handle the value */
        if (strcmp(name, "signer") == 0)
        {
            OE_CHECK(_ascii_to_binary(
                p, sigstruct->signer.buf, sizeof(sigstruct->signer)));
        }
        else if (strcmp(name, "appid") == 0)
        {
            OE_CHECK(_ascii_to_binary(
                p, sigstruct->appid.buf, sizeof(sigstruct->appid)));
        }
        else if (strcmp(name, "apphash") == 0)
        {
            OE_CHECK(_ascii_to_binary(
                p, sigstruct->apphash.buf, sizeof(sigstruct->apphash)));
        }
        else if (strcmp(name, "signature") == 0)
        {
            OE_CHECK(_ascii_to_binary(
                p, sigstruct->signature.buf, sizeof(sigstruct->signature)));
        }
        else
        {
            OE_RAISE(OE_FAILURE);
        }
    }

    result = OE_OK;

done:

    if (is)
        fclose(is);

    return result;
}

static oe_result_t _put(
    FILE* os,
    const char* name,
    const uint8_t* data,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;

    if ((size_t)fprintf(os, "%s=", name) != strlen(name) + 1)
        OE_RAISE(OE_FAILURE);

    for (size_t i = 0; i < size; i++)
    {
        if (fprintf(os, "%02x", data[i]) != 2)
            OE_RAISE(OE_FAILURE);
    }

    if (fprintf(os, "\n") != 1)
        OE_RAISE(OE_FAILURE);

done:
    return result;
}

oe_result_t oe_app_save_sigstruct(
    const char* path,
    const oe_app_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    FILE* os = NULL;
    const oe_app_sigstruct_t* p = sigstruct;

    if (!path || !sigstruct)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(os = fopen(path, "w")))
        OE_RAISE(OE_NOT_FOUND);

    fprintf(os, "# sigstruct\n");

    OE_CHECK(_put(os, "signer", p->signer.buf, sizeof(p->signer)));
    OE_CHECK(_put(os, "appid", p->appid.buf, sizeof(p->appid)));
    OE_CHECK(_put(os, "apphash", p->apphash.buf, sizeof(p->apphash)));
    OE_CHECK(_put(os, "signature", p->signature.buf, sizeof(p->signature)));

    result = OE_OK;

done:

    if (os)
        fclose(os);

    return result;
}
