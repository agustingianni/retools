project(cli_debugger CXX)

add_executable(
	cli_debugger
	${CMAKE_CURRENT_SOURCE_DIR}/cli_debugger.cpp
)

# Link to libdisassembly.
target_link_libraries(
	cli_debugger
	target_debug
)
