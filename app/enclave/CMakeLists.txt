# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oeappenclave STATIC app.c ../common/app.c)

maybe_build_using_clangw(oeappenclave)

target_link_libraries(oeappenclave PUBLIC oecryptombed)

install(TARGETS oeappenclave EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
