cmake_minimum_required(VERSION 2.8)

project(harness_libbinary)

add_executable(
	harness_libbinary
	${CMAKE_CURRENT_SOURCE_DIR}/harness_libbinary.cpp
)

# Link to libdisassembly.
target_link_libraries(
	harness_libbinary
	binary
)
