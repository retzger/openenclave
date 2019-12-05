# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oeapphost STATIC app.c)

maybe_build_using_clangw(oeapphost)

target_link_libraries(oeapphost PUBLIC oehost)

install(TARGETS oeapphost EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
