cmake_minimum_required(VERSION 2.8)

project(cli_emulator)

add_executable(
	cli_emulator
	${CMAKE_CURRENT_SOURCE_DIR}/cli_emulator.cpp
)

# Enable c++11 on the target.
set_target_properties(
	cli_emulator
	PROPERTIES
	COMPILE_FLAGS "-std=c++11"
)

# Link to libdisassembly.
target_link_libraries(
	cli_emulator
	disassembly
	emulation
)
