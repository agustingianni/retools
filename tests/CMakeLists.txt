cmake_minimum_required(VERSION 2.8)

project(instruction_fuzz)

find_package(Boost REQUIRED)

# Find the paths to capstone's stuff.
find_path(CAPSTONE_INCLUDE_DIR NAMES capstone/capstone.h)
find_library(CAPSTONE_LIBRARIES NAMES capstone)

# Find the paths to darm's stuff.
find_path(DARM_INCLUDE_DIR NAMES darm.h PATHS /Users/anon/workspace/darm)
find_library(DARM_LIBRARIES NAMES darm PATHS /Users/anon/workspace/darm)

message("-- Include dirs of CAPSTONE  : " ${CAPSTONE_INCLUDE_DIR} )
message("-- Library dirs of CAPSTONE  : " ${CAPSTONE_LIBRARIES} )
message("-- Include dirs of DARM  : " ${DARM_INCLUDE_DIR} )
message("-- Library dirs of DARM  : " ${DARM_LIBRARIES} )
message("-- Include dirs of boost     : " ${Boost_INCLUDE_DIRS} )

include_directories(
	${Boost_INCLUDE_DIRS}
	${CAPSTONE_INCLUDE_DIR}
	${DARM_INCLUDE_DIR}
)

add_executable(
	instruction_fuzz
	${CMAKE_CURRENT_SOURCE_DIR}/instruction_fuzz.cpp
)

# Enable c++11 on the target.
set_target_properties(
	instruction_fuzz
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

target_link_libraries(
	instruction_fuzz
	disassembly
	${CAPSTONE_LIBRARIES}
	${DARM_LIBRARIES}
)

