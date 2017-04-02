cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libdebug CXX)

# Find LLDB.
find_library(
	LLDB_LIBRARY
	NAMES LLDB
	PATHS "/Applications/Xcode.app/Contents/SharedFrameworks"
	ENV LIBRARY_PATH
	ENV LD_LIBRARY_PATH
)

find_path(
	LLDB_LIBRARY_INCLUDES
	lldb/API/LLDB.h
	PATHS
	${CMAKE_SOURCE_DIR}/third_party/lldb/include
)

message("-- Found LLDB libraries : " ${LLDB_LIBRARY})
message("-- Found LLDB includes  : " ${LLDB_LIBRARY_INCLUDES})

add_library(
	target_debug
	STATIC
	${CMAKE_CURRENT_SOURCE_DIR}/src/Debugger.cpp
)

add_dependencies(
	target_debug
	target_lldb_includes
)

target_link_libraries(
	target_debug
	${LLDB_LIBRARY}
)

target_include_directories(
    target_debug
	PUBLIC ${CMAKE_SOURCE_DIR}/src/utilities
	PUBLIC ${LLDB_LIBRARY_INCLUDES}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)