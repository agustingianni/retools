cmake_minimum_required(VERSION 2.8)

project(random)

# Find the paths to unicorn's stuff.
find_path(UNICORN_INCLUDE_DIR NAMES unicorn/unicorn.h)
find_library(UNICORN_LIBRARIES NAMES unicorn)

# For some reason unicorn on linux is not linked with threads so we need to link it ourselves.
find_package(Threads)

message("-- Include dirs of UNICORN  : " ${UNICORN_INCLUDE_DIR} )
message("-- Library dirs of UNICORN  : " ${UNICORN_LIBRARIES} )

add_executable(
	random
	${CMAKE_CURRENT_SOURCE_DIR}/random.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../test_utils.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../test_utils.h
)

target_include_directories(
	random
	PRIVATE
	${UNICORN_INCLUDE_DIR}
	../../
)

target_link_libraries(
	random
	emulation
	disassembly
	capstone
	${UNICORN_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
)
