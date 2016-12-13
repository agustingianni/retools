cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libdisassembly CXX)

# Create the library target.
add_library(
	disassembly
	SHARED
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMArch.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMArch.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMUtilities.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMtoStringCustom.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMtoStringCustom.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMDecodingTable.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMDecodingTable.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoString.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMtoString.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/gen/ARMInstructionFields.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Address.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/BasicBlock.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Graph.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/FlowGraph.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Function.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Instruction.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Module.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Operand.h
	${CMAKE_SOURCE_DIR}/src/utilities/Utilities.h
)

# Avoid specific warnings on the target.
set_target_properties(
	disassembly
	PROPERTIES
	COMPILE_FLAGS "-Wno-unused-function -Wno-parentheses-equality -Wno-unused-variable -Wno-int-to-void-pointer-cast"
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
)
