# Create a new project.
project(libemulation CXX)

# Create the library target.
add_library(
	emulation
	SHARED
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.h
	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/arm/gen/ARMInterpreter.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../libdisassembly/arm/gen/ARMInterpreter.h
)

# Avoid specific warnings in the target.
set_target_properties(
	emulation
	PROPERTIES
	COMPILE_FLAGS "-Wno-parentheses-equality"
)

target_link_libraries(
	emulation
	disassembly
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
