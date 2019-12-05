# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oeextenclave STATIC ext.c ../common/ext.c)

maybe_build_using_clangw(oeextenclave)

target_link_libraries(oeextenclave PUBLIC oecryptombed)

install(TARGETS oeextenclave EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
