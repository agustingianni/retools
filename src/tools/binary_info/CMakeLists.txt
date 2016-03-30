cmake_minimum_required(VERSION 2.8)

project(binary_info)

add_executable(
	binary_info
	${CMAKE_CURRENT_SOURCE_DIR}/binary_info.cpp
)

# Enable c++11 on the target.
set_target_properties(
	binary_info
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

# Link to libdisassembly.
target_link_libraries(
	binary_info
	binary
)
