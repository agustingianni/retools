# Create a new project.
project(libinstrumentation CXX)

# Create the library target.
add_library(
	instrumentation
	SHARED
	${CMAKE_SOURCE_DIR}/src/libinstrumentation/
)

# Set target specific include directories.
target_include_directories(
 	instrumentation
 	PRIVATE
 	${CMAKE_SOURCE_DIR}/src/libinstrumentation
)