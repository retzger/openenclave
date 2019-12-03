# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../oeapp.edl enclave gen)

add_enclave(TARGET oeapp_enc UUID 84400f49-9e35-4fcf-8b15-9e38761266e3 SOURCES enc.c ${gen})

target_include_directories(oeapp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeapp_enc oeappenclave oelibc)
