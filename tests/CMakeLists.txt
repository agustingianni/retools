cmake_minimum_required(VERSION 2.8)

project(instruction_fuzz)

find_package(Boost REQUIRED)

add_executable(
	instruction_fuzz
	${CMAKE_CURRENT_SOURCE_DIR}/instruction_fuzz.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/test_utils.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/test_utils.h
)

target_include_directories(
	instruction_fuzz
	PRIVATE
	${Boost_INCLUDE_DIRS}
)

target_link_libraries(
	instruction_fuzz
	disassembly
	capstone
	darm
)

add_subdirectory(libemulation/arm)