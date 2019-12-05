# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oeexthost STATIC ext.c ../common/ext.c)

maybe_build_using_clangw(oeexthost)

target_link_libraries(oeexthost PUBLIC oehost)

install(TARGETS oeexthost EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
