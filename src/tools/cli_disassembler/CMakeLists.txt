cmake_minimum_required(VERSION 2.8)

project(cli_disassembler)

add_executable(
	cli_disassembler
	${CMAKE_CURRENT_SOURCE_DIR}/cli_disassembler.cpp
)

# Enable c++11 on the target.
set_target_properties(
	cli_disassembler
	PROPERTIES
	COMPILE_FLAGS "-std=c++11"
)

# Link to libdisassembly.
target_link_libraries(
	cli_disassembler
	disassembly
)
