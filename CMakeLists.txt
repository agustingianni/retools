cmake_minimum_required(VERSION 2.8)

# Disable C++ exceptions and enable C++11 globaly.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -g -Wno-int-to-void-pointer-cast")

# Build related libraries.
add_subdirectory(src/libbinary)
add_subdirectory(src/libdisassembly)
# add_subdirectory(src/libemulation)
# add_subdirectory(src/libsymbolic)

# Build the tools.
add_subdirectory(src/tools)

project(retools)

add_executable(
	retools
	${CMAKE_CURRENT_SOURCE_DIR}/src/retools.cpp
)

target_include_directories(
	retools
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/src/libbinary
)

# Enable c++11 on the target.
set_target_properties(
	retools
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

target_link_libraries(
	retools
	binary
)
