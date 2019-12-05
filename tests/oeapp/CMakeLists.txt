# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

set(PUBKEY "${CMAKE_CURRENT_BINARY_DIR}/public.pem")
set(PRIVKEY "${CMAKE_CURRENT_BINARY_DIR}/private.pem")
set(APPID cc79fdaf950d4317bd54379bc711f0ddfc5f45593043410d875ba7edba3a5ac2)
set(APPHASH 042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24)
set(SIGSTRUCT ${CMAKE_CURRENT_BINARY_DIR}/sigstruct)

# Generate a self-signed private key:
add_test(tests/oeapp_privkey
    openssl genrsa -out ${PRIVKEY} -3 3072)

# Generate a public key from the private key:
add_test(tests/oeapp_pubkey
    openssl rsa -in ${PRIVKEY} -out ${PUBKEY} -pubout -outform PEM)

# Update the policy within the enclave:
add_test(tests/oeapp_update
    oeapp update
    pubkey=${PUBKEY}
    appid=${APPID}
    enclave=${CMAKE_CURRENT_BINARY_DIR}/enc/oeapp_enc
    symbol=policy)

# Sign the hash and create the sigstruct file:
add_test(tests/oeapp_sign
    oeapp sign
    privkey=${PRIVKEY}
    appid=${APPID}
    apphash=${APPHASH}
    sigstructfile=${SIGSTRUCT})

add_enclave_test(tests/oeapp_verify
    oeapp_host oeapp_enc ${SIGSTRUCT} ${APPHASH})
