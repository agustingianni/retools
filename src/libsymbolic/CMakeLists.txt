# Create a new project.
project(libsymbolic CXX)

# Create the library target.
add_library(
	symbolic
	SHARED
	${CMAKE_SOURCE_DIR}/src/libsymbolic/
)

# Set target specific include directories.
target_include_directories(
 	symbolic
 	PRIVATE
 	${CMAKE_SOURCE_DIR}/src/libsymbolic
)