# Create a new project.
project(libdisassembly CXX)

# Get the paths of the generated files for the decoder.
get_target_property(GENERATED_FILES_DIRECTORY libspec_arm_decoder GENERATED_FILES_DIRECTORY)
get_target_property(GENERATED_FILES libspec_arm_decoder GENERATED_FILES)
set_source_files_properties(${GENERATED_FILES} PROPERTIES GENERATED TRUE)

message("GENERATED_FILES_DIRECTORY=${GENERATED_FILES_DIRECTORY}")

# Create the library target.
add_library(
	disassembly
	SHARED
	${GENERATED_FILES}
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMDisassembler.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMArch.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMArch.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMUtilities.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMtoStringCustom.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMtoStringCustom.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Address.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/BasicBlock.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Graph.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/FlowGraph.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Function.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Instruction.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Module.h
	${CMAKE_CURRENT_SOURCE_DIR}/generic/Operand.h
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
	${GENERATED_FILES_DIRECTORY}
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(
	disassembly
	utilities
)

# Add a dependency to the generated files.
add_dependencies(disassembly libspec_arm_decoder)