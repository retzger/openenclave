// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/ext.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/files.h>
#include <openenclave/internal/raise.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../host/crypto/rsa.h"

static const char* arg0;

OE_PRINTF_FORMAT(1, 2)
static void _err(const char* format, ...)
{
    fprintf(stderr, "\n");

    fprintf(stderr, "%s: error: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n\n");

    exit(1);
}

static bool _valid_symbol_name(const char* name)
{
    bool ret = false;
    const char* p = name;

    if (*p != '_' && !isalpha(*p))
        goto done;

    p++;

    while (*p == '_' || isalnum(*p))
        p++;

    if (*p != '\0')
        goto done;

    ret = true;

done:
    return ret;
}

static uint64_t _find_file_offset(elf64_t* elf, uint64_t vaddr)
{
    elf64_ehdr_t* eh = (elf64_ehdr_t*)elf->data;
    elf64_phdr_t* ph = (elf64_phdr_t*)((uint8_t*)elf->data + eh->e_phoff);
    size_t i;

    /* Search for the segment that contains this virtual address. */
    for (i = 0; i < eh->e_phnum; i++)
    {
        if (vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_memsz)
        {
            size_t vaddr_offset = vaddr - ph->p_vaddr;

            /* Calculate the offset within the file. */
            size_t file_offset = ph->p_offset + vaddr_offset;

            if (file_offset >= elf->size)
                return (uint64_t)-1;

            return file_offset;
        }

        ph++;
    }

    return (uint64_t)-1;
}

static void _compute_sha256_hash(
    oe_ext_hash_t* hash,
    const void* data,
    size_t size)
{
    oe_sha256_context_t context;
    OE_SHA256 sha256;

    oe_sha256_init(&context);
    oe_sha256_update(&context, data, size);
    oe_sha256_final(&context, &sha256);
    memcpy(hash, sha256.buf, OE_SHA256_SIZE);
}

static int _write_file(const char* path, const void* data, size_t size)
{
    FILE* os;

    if (!(os = fopen(path, "wb")))
        return -1;

    if (fwrite(data, 1, size, os) != size)
        return -1;

    fclose(os);

    return 0;
}

static void _mem_reverse(void* dest_, const void* src_, size_t n)
{
    unsigned char* dest = (unsigned char*)dest_;
    const unsigned char* src = (const unsigned char*)src_;
    const unsigned char* end = src + n;

    while (n--)
        *dest++ = *--end;
}

static oe_result_t _get_modulus(
    const oe_rsa_public_key_t* rsa,
    uint8_t modulus[OE_EXT_KEY_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_EXT_KEY_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !modulus)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_modulus(rsa, buf, &bufsize));

    /* RSA key length is the modulus length, so these have to be equal. */
    if (bufsize != OE_EXT_KEY_SIZE)
        OE_RAISE(OE_FAILURE);

    _mem_reverse(modulus, buf, bufsize);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_exponent(
    const oe_rsa_public_key_t* rsa,
    uint8_t exponent[OE_EXT_EXPONENT_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_EXT_EXPONENT_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !exponent)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_exponent(rsa, buf, &bufsize));

    /* Exponent is in big endian. So, we need to reverse. */
    _mem_reverse(exponent, buf, bufsize);

    /* We zero out the rest to get the right exponent in little endian. */
    memset(exponent + bufsize, 0, OE_EXT_EXPONENT_SIZE - bufsize);

    result = OE_OK;

done:
    return result;
}

static int _get_opt(
    int* argc,
    const char* argv[],
    const char* name,
    const char** opt)
{
    size_t len = strlen(name);

    for (int i = 0; i < *argc; i++)
    {
        if (strncmp(argv[i], name, len) == 0 && argv[i][len] == '=')
        {
            *opt = &argv[i][len + 1];
            size_t n = (size_t)(*argc - i) * sizeof(char*);
            memmove(&argv[i], &argv[i + 1], n);
            (*argc)--;
            return 0;
        }
    }

    /* Not found */
    return -1;
}

static int _extend_main(int argc, const char* argv[])
{
    int ret = 1;
    static const char _usage[] =
        "\n"
        "Usage: %s extend pubkey=? extid=? enclave=? symbol=? [payload=?]\n"
        "\n";
    typedef struct
    {
        const char* pubkey;
        oe_ext_hash_t extid;
        const char* enclave;
        const char* symbol;
        const char* payload;
    } opts_t;
    opts_t opts;
    elf64_t elf;
    bool loaded = false;
    elf64_sym_t sym;
    uint8_t* symbol_address;
    size_t file_offset;
    void* pem_data = NULL;
    size_t pem_size = 0;
    void* payload_data = NULL;
    size_t payload_size = 0;
    oe_rsa_public_key_t pubkey;
    bool pubkey_initialized = false;

    memset(&opts, 0, sizeof(opts));

    /* Check and collect arguments. */
    if (argc == 2)
    {
        fprintf(stderr, _usage, arg0);
        goto done;
    }

    /* Collect the options. */
    {
        /* Handle pubkey option. */
        if (_get_opt(&argc, argv, "pubkey", &opts.pubkey) != 0)
            _err("missing pubkey option");

        /* Get the extid option. */
        {
            const char* ascii;

            if (_get_opt(&argc, argv, "extid", &ascii) != 0)
                _err("missing 'extid' option");

            if (oe_ext_ascii_to_hash(ascii, &opts.extid) != OE_OK)
                _err("bad 'extid' option: %s", ascii);
        }

        /* Handle enclave option. */
        if (_get_opt(&argc, argv, "enclave", &opts.enclave) != 0)
            _err("missing 'enclave' option");

        /* Get symbol option. */
        {
            if (_get_opt(&argc, argv, "symbol", &opts.symbol) != 0)
                _err("missing symbol option");

            if (!_valid_symbol_name(opts.symbol))
                _err("bad value for symbol option: %s", opts.symbol);
        }

        /* Get optional payload option. */
        _get_opt(&argc, argv, "payload", &opts.payload);

        if (payload_size >= OE_EXT_PAYLOAD_SIZE)
        {
            _err(
                "payload is too large (cannot be bigger than %u)",
                OE_EXT_PAYLOAD_SIZE);
        }
    }

    /* Fail if there are unconsumed option. */
    if (argc > 2)
    {
        _err("unknown option: %s", argv[2]);
    }

    /* Load the ELF-64 object */
    {
        if (elf64_load(opts.enclave, &elf) != 0)
            _err("cannot load %s", opts.enclave);

        loaded = true;
    }

    /* Find the symbol within the ELF image. */
    if (elf64_find_symbol_by_name(&elf, opts.symbol, &sym) != 0)
        _err("cannot find symbol: %s", opts.symbol);

    /* Check the size of the symbol. */
    if (sym.st_size != sizeof(oe_ext_policy_t))
        _err("symbol %s is wrong size", opts.symbol);

    /* Find the offset within the ELF file of this symbol. */
    if ((file_offset = _find_file_offset(&elf, sym.st_value)) == (uint64_t)-1)
        _err("cannot locate symbol %s in %s", opts.symbol, opts.enclave);

    /* Make sure the entire symbol falls within the file image. */
    if (file_offset + sizeof(oe_ext_policy_t) >= elf.size)
        _err("unexpected");

    /* Get the address of the symbol. */
    symbol_address = (uint8_t*)elf.data + file_offset;

    /* Load the public key. */
    {
        if (__oe_load_file(opts.pubkey, 1, &pem_data, &pem_size) != 0)
            _err("failed to load keyfile: %s", opts.pubkey);

        pem_size++;
    }

    /* Load the profile if any. */
    if (opts.payload)
    {
        if (__oe_load_file(opts.payload, 1, &payload_data, &payload_size) != 0)
            _err("failed to load payload file: %s", opts.payload);
    }

    /* Initialize the RSA private key. */
    if (oe_rsa_public_key_read_pem(&pubkey, pem_data, pem_size) != OE_OK)
        _err("failed to initialize private key");

    /* Update the 'policy' symbol. */
    {
        oe_ext_policy_t policy;
        memset(&policy, 0, sizeof(policy));

        /* policy.modulus */
        if (_get_modulus(&pubkey, policy.pubkey.modulus) != 0)
            _err("failed to get modulus");

        /* policy.exponent */
        if (_get_exponent(&pubkey, policy.pubkey.exponent) != 0)
            _err("failed to get exponent");

        /* policy.extid */
        policy.extid = opts.extid;

        /* Expecting an exponent of 03000000 */
        {
            uint8_t buf[OE_EXT_EXPONENT_SIZE] = {
                0x03,
                0x00,
                0x00,
                0x00,
            };

            if (memcmp(policy.pubkey.exponent, buf, sizeof(buf)) != 0)
                _err("bad value for pubkey exponent (must be 3)");
        }

        /* Compute the hash of the public key. */
        _compute_sha256_hash(
            &policy.signer,
            policy.pubkey.modulus,
            sizeof(policy.pubkey.modulus));

        /* Inject the payload if any. */
        if (payload_data && payload_size)
        {
            memcpy(policy.payload, payload_data, payload_size);
            policy.payload_size = payload_size;
        }

        /* Update the policy structure in the ELF file. */
        memcpy(symbol_address, &policy, sizeof(policy));
    }

    /* Rewrite the file. */
    if (_write_file(opts.enclave, elf.data, elf.size) != 0)
    {
        _err("failed to write: %s", opts.enclave);
        goto done;
    }

    ret = 0;

done:

    if (pem_data)
        free(pem_data);

    if (payload_data)
        free(payload_data);

    if (loaded)
        elf64_unload(&elf);

    if (pubkey_initialized)
        oe_rsa_public_key_free(&pubkey);

    return ret;
}

static int _dump_policy_main(int argc, const char* argv[])
{
    static const char _usage[] = "\n"
                                 "Usage: %s dump_policy enclave=? symbol=?\n"
                                 "\n";
    typedef struct
    {
        const char* enclave;
        const char* symbol;
    } opts_t;
    opts_t opts;
    elf64_t elf;
    bool loaded = false;
    elf64_sym_t sym;
    uint8_t* symbol_address;
    size_t file_offset;

    int ret = 1;

    /* Check and collect arguments. */
    if (argc != 4)
    {
        fprintf(stderr, _usage, arg0);
        goto done;
    }

    /* Collect the options. */
    {
        /* Handle enclave option. */
        if (_get_opt(&argc, argv, "enclave", &opts.enclave) != 0)
            _err("missing enclave option");

        /* Get symbol option. */
        {
            if (_get_opt(&argc, argv, "symbol", &opts.symbol) != 0)
                _err("missing symbol option");

            if (!_valid_symbol_name(opts.symbol))
                _err("bad value for symbol option: %s", opts.symbol);
        }
    }

    /* Load the ELF-64 object */
    {
        if (elf64_load(opts.enclave, &elf) != 0)
            _err("cannot load %s", opts.enclave);

        loaded = true;
    }

    /* Find the symbol within the ELF image. */
    if (elf64_find_symbol_by_name(&elf, opts.symbol, &sym) != 0)
        _err("cannot find symbol: %s", opts.symbol);

    /* Check the size of the symbol. */
    if (sym.st_size != sizeof(oe_ext_policy_t))
        _err("symbol %s is wrong size", opts.symbol);

    /* Find the offset within the ELF file of this symbol. */
    if ((file_offset = _find_file_offset(&elf, sym.st_value)) == (uint64_t)-1)
        _err("cannot locate symbol %s in %s", opts.symbol, opts.enclave);

    /* Make sure the entire symbol falls within the file image. */
    if (file_offset + sizeof(oe_ext_policy_t) >= elf.size)
        _err("unexpected");

    /* Get the address of the symbol. */
    symbol_address = (uint8_t*)elf.data + file_offset;

    /* Print the 'policy' symbol. */
    {
        oe_ext_policy_t policy;

        /* Update the policy structure in the ELF file. */
        memcpy(&policy, symbol_address, sizeof(policy));

        oe_ext_dump_policy(&policy);
    }

    ret = 0;

done:

    if (loaded)
        elf64_unload(&elf);

    return ret;
}

static int _sign_main(int argc, const char* argv[])
{
    static const char _usage[] =
        "\n"
        "Usage: %s sign privkey=? extid=? exthash=? sigstructfile=?\n"
        "\n";
    typedef struct
    {
        const char* privkey;
        oe_ext_hash_t extid;
        oe_ext_hash_t exthash;
        const char* sigstructfile;
    } opts_t;
    opts_t opts;
    void* pem_data = NULL;
    size_t pem_size = 0;
    oe_rsa_private_key_t rsa_private;
    bool rsa_private_initialized = false;
    oe_rsa_public_key_t pubkey;
    bool pubkey_initialized = false;
    oe_ext_sigstruct_t sigstruct;

    int ret = 1;

    /* Check usage. */
    if (argc != 6)
    {
        fprintf(stderr, _usage, arg0);
        goto done;
    }

    /* Collect the options. */
    {
        /* Get pubkey option. */
        if (_get_opt(&argc, argv, "privkey", &opts.privkey) != 0)
            _err("missing privkey option");

        /* Get the extid option. */
        {
            const char* ascii;

            if (_get_opt(&argc, argv, "extid", &ascii) != 0)
                _err("missing extid option");

            if (oe_ext_ascii_to_hash(ascii, &opts.extid) != OE_OK)
                _err("bad extid option: %s", ascii);
        }

        /* Get the exthash option. */
        {
            const char* ascii;

            if (_get_opt(&argc, argv, "exthash", &ascii) != 0)
                _err("missing exthash option");

            if (oe_ext_ascii_to_hash(ascii, &opts.exthash) != OE_OK)
                _err("bad exthash option: %s", ascii);
        }

        /* Get the sigstructfile option. */
        if (_get_opt(&argc, argv, "sigstructfile", &opts.sigstructfile) != 0)
            _err("missing sigstructfile option");
    }

    /* Load the private key. */
    {
        if (__oe_load_file(opts.privkey, 1, &pem_data, &pem_size) != 0)
            _err("failed to load privkey: %s", opts.privkey);

        pem_size++;
    }

    /* Initialize the RSA private key. */
    if (oe_rsa_private_key_read_pem(&rsa_private, pem_data, pem_size) != OE_OK)
        _err("failed to initialize private key");
    rsa_private_initialized = true;

    /* Get the RSA public key. */
    if (oe_rsa_get_public_key_from_private(&rsa_private, &pubkey) != OE_OK)
        _err("failed to get public key");
    pubkey_initialized = true;

    /* Perform the signing operation. */
    {
        uint8_t signature[OE_EXT_KEY_SIZE];
        oe_ext_hash_t hash;

        /* Combine the two hashes (extid and exthash) into one */
        {
            oe_sha256_context_t context;
            OE_SHA256 sha256;

            oe_sha256_init(&context);
            oe_sha256_update(&context, opts.extid.buf, sizeof(opts.extid));
            oe_sha256_update(&context, opts.exthash.buf, sizeof(opts.exthash));
            oe_sha256_final(&context, &sha256);

            memcpy(hash.buf, sha256.buf, sizeof(hash));
        }

        /* Create the signature from the hash. */
        {
            size_t signature_size = OE_EXT_KEY_SIZE;

            if (oe_rsa_private_key_sign(
                    &rsa_private,
                    OE_HASH_TYPE_SHA256,
                    hash.buf,
                    sizeof(oe_ext_hash_t),
                    signature,
                    &signature_size) != 0)
            {
                _err("signing operation failed");
            }

            if (signature_size != OE_EXT_KEY_SIZE)
                _err("bad resulting signature size");
        }

        /* Initialize the sigstruct structure. */
        {
            uint8_t modulus[OE_EXT_KEY_SIZE];
            uint8_t exponent[OE_EXT_EXPONENT_SIZE];

            memset(&sigstruct, 0, sizeof(sigstruct));

            /* Get the modulus */
            if (_get_modulus(&pubkey, modulus) != 0)
                _err("failed to get modulus");

            /* Get the exponent */
            if (_get_exponent(&pubkey, exponent) != 0)
                _err("failed to get exponent");

            /* sign.signer */
            _compute_sha256_hash(&sigstruct.signer, modulus, sizeof(modulus));

            /* sign.extid*/
            assert(sizeof sigstruct.extid == sizeof opts.extid);
            sigstruct.extid = opts.extid;

            /* sign.exthash*/
            assert(sizeof sigstruct.exthash == sizeof opts.exthash);
            sigstruct.exthash = opts.exthash;

            /* sign.signature */
            assert(sizeof sigstruct.signature == sizeof signature);
            memcpy(
                sigstruct.signature.buf, signature, sizeof sigstruct.signature);
        }
    }

    /* Save the sigstruct to a file. */
    if (oe_ext_save_sigstruct(opts.sigstructfile, &sigstruct) != OE_OK)
    {
        _err("failed to save: %s", opts.sigstructfile);
        goto done;
    }

    ret = 0;

done:

    if (pem_data)
        free(pem_data);

    if (rsa_private_initialized)
        oe_rsa_private_key_free(&rsa_private);

    if (pubkey_initialized)
        oe_rsa_public_key_free(&pubkey);

    return ret;
}

int main(int argc, const char* argv[])
{
    static const char _usage[] =
        "\n"
        "Usage: %s command options...\n"
        "\n"
        "Commands:\n"
        "    extend - inject a policy into an enclave.\n"
        "    sign - create a sigstruct file for a given signer and hash.\n"
        "    dump_policy - dump an enclave update sructure.\n"
        "\n";
    int ret = 1;

    arg0 = argv[0];

    if (argc < 2)
    {
        fprintf(stderr, _usage, argv[0]);
        goto done;
    }

    /* Disable logging noise to standard output. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    if (strcmp(argv[1], "extend") == 0)
    {
        ret = _extend_main(argc, argv);
        goto done;
    }
    else if (strcmp(argv[1], "sign") == 0)
    {
        ret = _sign_main(argc, argv);
        goto done;
    }
    if (strcmp(argv[1], "dump_policy") == 0)
    {
        ret = _dump_policy_main(argc, argv);
        goto done;
    }
    else
    {
        _err("unknown subcommand: %s", argv[1]);
    }

done:
    return ret;
}
