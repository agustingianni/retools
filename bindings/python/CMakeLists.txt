cmake_minimum_required(VERSION 2.8)

project(disassembler)

find_package(PythonInterp REQUIRED)
find_package(PythonLibs REQUIRED)
find_package(Boost COMPONENTS python REQUIRED)

message("-- Include dirs of boost  : " ${Boost_INCLUDE_DIRS} )
message("-- Libs of boost          : " ${Boost_LIBRARIES} )
message("-- Include dirs of python : " ${PYTHON_INCLUDE_DIRS} )
message("-- Libs of python         : " ${PYTHON_LIBRARIES} )

include_directories(
	${Boost_INCLUDE_DIRS}
	${PYTHON_INCLUDE_DIRS}
)

add_library(
	disassembler
	SHARED
	${CMAKE_CURRENT_SOURCE_DIR}/libdisassembly.cpp
)

# Enable c++11 on the target.
set_target_properties(
	disassembler
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

target_link_libraries(
	disassembler
	disassembly
	${Boost_LIBRARIES}
	${PYTHON_LIBRARIES}
)

