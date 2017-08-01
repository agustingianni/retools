cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libspec CXX)

add_executable(
	target_spec
	${CMAKE_CURRENT_SOURCE_DIR}/src/libspec.cpp
)

target_include_directories(
    target_spec
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)