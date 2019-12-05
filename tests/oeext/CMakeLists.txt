# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

set(PUBKEY "${CMAKE_CURRENT_BINARY_DIR}/public.pem")
set(PRIVKEY "${CMAKE_CURRENT_BINARY_DIR}/private.pem")
set(EXTID cc79fdaf950d4317bd54379bc711f0ddfc5f45593043410d875ba7edba3a5ac2)
set(EXTHASH 042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24)
set(SIGSTRUCT ${CMAKE_CURRENT_BINARY_DIR}/sigstruct)
set(PAYLOAD ${CMAKE_CURRENT_SOURCE_DIR}/payload)

# Generate a self-signed private key:
add_test(tests/oeext_privkey
    openssl genrsa -out ${PRIVKEY} -3 3072)

# Generate a public key from the private key:
add_test(tests/oeext_pubkey
    openssl rsa -in ${PRIVKEY} -out ${PUBKEY} -pubout -outform PEM)

# Update the policy within the enclave:
add_test(tests/oeext_extend
    oeext extend
    pubkey=${PUBKEY}
    extid=${EXTID}
    enclave=${CMAKE_CURRENT_BINARY_DIR}/enc/oeext_enc
    symbol=policy
    payload=${PAYLOAD})

# Sign the hash and create the sigstruct file:
add_test(tests/oeext_sign
    oeext sign
    privkey=${PRIVKEY}
    extid=${EXTID}
    exthash=${EXTHASH}
    sigstructfile=${SIGSTRUCT})

add_enclave_test(tests/oeext_verify
    oeext_host oeext_enc ${SIGSTRUCT} ${EXTHASH})
