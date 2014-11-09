cmake_minimum_required(VERSION 2.8)

project(disassembler_project)

include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/src"
	"${CMAKE_CURRENT_SOURCE_DIR}/src/disassembly/arm/gen"
)

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -O3 -Wno-unused-function -Wno-parentheses-equality -Wno-unused-variable")

add_executable(
	retools
	src/retools.cpp
	src/disassembly/generic/AbstractDisassembler.cpp
	src/disassembly/generic/AbstractDisassembler.h
	src/disassembly/arm/ARMDisassembler.cpp
	src/disassembly/arm/ARMDisassembler.h
	src/disassembly/arm/ARMUtilities.h
	src/disassembly/arm/gen/ARMv7Decoder.cpp
	src/disassembly/arm/gen/ARMv7Decoder.h
	src/disassembly/arm/gen/ARMv7toString.cpp
	src/disassembly/arm/gen/ARMv7toString.h
	src/utilities/Utilities.h
)

install(TARGETS retools DESTINATION bin)
