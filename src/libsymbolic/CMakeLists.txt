cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libsymbolic CXX)

# Create the library target.
add_library(
	symbolic
	SHARED
	${CMAKE_SOURCE_DIR}/src/libsymbolic/
)

# Enable c++11 on the target.
set_target_properties(
	symbolic
	PROPERTIES
	COMPILE_FLAGS "-std=c++11"
)

# Set target specific include directories.
target_include_directories(
 	symbolic
 	PRIVATE
 	${CMAKE_SOURCE_DIR}/src/libsymbolic
)