# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oeapp main.c)

target_link_libraries(oeapp oehost)

# assemble into proper collector dir
set_property(TARGET oeapp PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oeapp EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
