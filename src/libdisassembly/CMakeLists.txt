cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libdisassembly CXX)

# Create the library target.
add_library(
	disassembly
	STATIC
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMUtilities.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMDecodingTable.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMDecodingTable.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoString.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoString.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoStringCustom.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoStringCustom.h
	${CMAKE_SOURCE_DIR}/src/utilities/Utilities.h
)

# Enable c++11 on the target.
set_target_properties(
	disassembly
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11 -Wno-unused-function -Wno-parentheses-equality -Wno-unused-variable -Wno-int-to-void-pointer-cast"
)

# Set target specific include directories.
target_include_directories(
 	disassembly
 	PUBLIC
 	${CMAKE_CURRENT_SOURCE_DIR}				# Add the current directory as an include path.
 	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen		# Add the automatically generated headers as an include path.
 	${CMAKE_SOURCE_DIR}/src/utilities
)

target_link_libraries(
	disassembly
	capstone
	darm
)
