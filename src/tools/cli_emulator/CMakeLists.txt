project(cli_emulator)

add_executable(
	cli_emulator
	${CMAKE_CURRENT_SOURCE_DIR}/cli_emulator.cpp
)

# Link to libdisassembly.
target_link_libraries(
	cli_emulator
	emulation
	disassembly
)
