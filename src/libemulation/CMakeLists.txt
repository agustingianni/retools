cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libemulation CXX)

# Create the library target.
add_library(
	emulation
	STATIC
	${CMAKE_SOURCE_DIR}/src/libemulation/
)

# Enable c++11 on the target.
set_target_properties(
	emulation
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

# Set target specific include directories.
target_include_directories(
 	emulation
 	PRIVATE
 	${CMAKE_SOURCE_DIR}/src/libemulation
)