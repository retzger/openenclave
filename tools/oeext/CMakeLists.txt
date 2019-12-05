# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oeext main.c)

target_link_libraries(oeext oeexthost oehost)

# assemble into proper collector dir
set_property(TARGET oeext PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oeext EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
