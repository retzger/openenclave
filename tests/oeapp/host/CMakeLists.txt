# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../oeapp.edl host gen)

add_executable(oeapp_host host.c ${gen})

add_dependencies(oeapp_host oeapp)

target_include_directories(oeapp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeapp_host oeapphost oehostapp)
