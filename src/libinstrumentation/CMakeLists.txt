cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libinstrumentation CXX)

# Create the library target.
add_library(
	instrumentation
	STATIC
	${CMAKE_SOURCE_DIR}/src/libinstrumentation/
)

# Enable c++11 on the target.
set_target_properties(
	instrumentation
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

# Set target specific include directories.
target_include_directories(
 	instrumentation
 	PRIVATE
 	${CMAKE_SOURCE_DIR}/src/libinstrumentation
)