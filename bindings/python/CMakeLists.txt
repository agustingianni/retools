project(disassembler_py)

find_package(PythonInterp REQUIRED)
find_package(PythonLibs REQUIRED)
find_package(Boost COMPONENTS python REQUIRED)

add_library(
	disassembler_py
	SHARED
	${CMAKE_CURRENT_SOURCE_DIR}/libdisassembly.cpp
)

target_link_libraries(
	disassembler_py
	disassembly
	${Boost_LIBRARIES}
	${PYTHON_LIBRARIES}
)

target_include_directories(
	disassembler_py
	PRIVATE ${PYTHON_INCLUDE_DIRS}
)

add_library(
	emulation_py
	SHARED
	${CMAKE_CURRENT_SOURCE_DIR}/libemulation.cpp
)

target_link_libraries(
	emulation_py
	emulation
	${Boost_LIBRARIES}
	${PYTHON_LIBRARIES}
)

target_include_directories(
	emulation_py
	PRIVATE ${PYTHON_INCLUDE_DIRS}
)
