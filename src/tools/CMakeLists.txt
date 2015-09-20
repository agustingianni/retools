cmake_minimum_required(VERSION 2.8)

project(tools)

add_executable(
	tools
	${CMAKE_CURRENT_SOURCE_DIR}/disassembler.cpp
)

# Enable c++11 on the target.
set_target_properties(
	tools
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

# Link to libdisassembly.
target_link_libraries(
	tools
	disassembly
)
