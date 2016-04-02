cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libemulation CXX)

# Create the library target.
add_library(
	emulation
	STATIC
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.h
	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/arm/gen/ARMInterpreter.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/arm/gen/ARMInterpreter.h
)

# Enable c++11 on the target.
set_target_properties(
	emulation
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11 -Wno-parentheses-equality"
)

# Set target specific include directories.
target_include_directories(
 	emulation
 	PUBLIC
 	${CMAKE_CURRENT_SOURCE_DIR}				# Add the current directory as an include path.
 	${CMAKE_CURRENT_SOURCE_DIR}/arm
 	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/
 	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/arm
 	${CMAKE_CURRENT_SOURCE_DIR}/../utilities
)
