# Create a new project.
project(libemulation CXX)

# Get the paths of the generated files for the decoder.
get_target_property(GENERATED_FILES_DIRECTORY libspec_arm_interpreter GENERATED_FILES_DIRECTORY)
get_target_property(GENERATED_FILES libspec_arm_interpreter GENERATED_FILES)
set_source_files_properties(${GENERATED_FILES} PROPERTIES GENERATED TRUE)

# Create the library target.
add_library(
	emulation
	SHARED
	${GENERATED_FILES}
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMEmulator.h
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/arm/ARMContext.h
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
	utilities
)

# Set target specific include directories.
target_include_directories(
 	emulation
 	PUBLIC
	${GENERATED_FILES_DIRECTORY}
 	${CMAKE_CURRENT_SOURCE_DIR}
 	${CMAKE_CURRENT_SOURCE_DIR}/arm
)

# Add a dependency to the generated files.
add_dependencies(emulation libspec_arm_interpreter)