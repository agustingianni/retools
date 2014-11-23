cmake_minimum_required(VERSION 2.8)

#set(CMAKE_C_COMPILER "/usr/local/bin/clang")
#set(CMAKE_CXX_COMPILER "/usr/local/bin/clang++")

project(disassembler_project)

include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/src"
	"${CMAKE_CURRENT_SOURCE_DIR}/src/disassembly/arm/gen"
)

#set(CMAKE_CXX_FLAGS "-std=c++11 -O1 -g -fsanitize=address -fno-omit-frame-pointer -Wall -Wno-unused-function -Wno-parentheses-equality -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "-std=c++11 -O1 -g -Wall -Wno-unused-function -Wno-parentheses-equality -Wno-unused-variable")

# Get some debugging information about the decoders.
#IF (DEFINED DEBUG_DECODER)
#	SET(DEBUG_DECODER 1)
#	ADD_DEFINITIONS(-DDEBUG_DECODER=${DEBUG_DECODER})
#	MESSAGE("Showing debug information on decode: ${DEBUG_DECODER}")
#ENDIF()

add_executable(
	retools
	src/retools.cpp
	src/disassembly/arm/ARMDisassembler.cpp
	src/disassembly/arm/ARMDisassembler.h
	src/disassembly/arm/ARMUtilities.h
	src/disassembly/arm/gen/ARMDecodingTable.cpp
	src/disassembly/arm/gen/ARMDecodingTable.h
	src/disassembly/arm/gen/ARMtoString.cpp
	src/disassembly/arm/gen/ARMtoString.h
	src/disassembly/arm/gen/ARMtoStringCustom.cpp
	src/disassembly/arm/gen/ARMtoStringCustom.h
	src/utilities/Utilities.h
)

add_executable(
	instruction_fuzz
	tests/instruction_fuzz.cpp
	src/disassembly/arm/ARMDisassembler.cpp
	src/disassembly/arm/ARMDisassembler.h
	src/disassembly/arm/ARMUtilities.h
	src/disassembly/arm/gen/ARMDecodingTable.cpp
	src/disassembly/arm/gen/ARMDecodingTable.h
	src/disassembly/arm/gen/ARMtoString.cpp
	src/disassembly/arm/gen/ARMtoString.h
	src/disassembly/arm/gen/ARMtoStringCustom.cpp
	src/disassembly/arm/gen/ARMtoStringCustom.h
	src/utilities/Utilities.h
)

find_package(Boost 1.56.0)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
endif()

target_link_libraries(
	instruction_fuzz
	capstone
	boost_regex
	darm
)

install(TARGETS retools DESTINATION bin)

enable_testing()

add_test(
	NAME instruction_fuzz
	COMMAND instruction_fuzz
)
