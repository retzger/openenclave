# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../oeext.edl enclave gen)

add_enclave(TARGET oeext_enc UUID 84400f49-9e35-4fcf-8b15-9e38761266e3 SOURCES enc.c ${gen})

target_include_directories(oeext_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeext_enc oeextenclave oelibc)
