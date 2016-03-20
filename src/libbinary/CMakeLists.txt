cmake_minimum_required(VERSION 2.8)

# Create a new project.
project(libbinary CXX)

# Create the library target.
add_library(
    binary
    STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AbstractBinary.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/EntryPoint.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Export.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Import.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Library.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Relocation.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Segment.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Segment.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/String.h
    ${CMAKE_CURRENT_SOURCE_DIR}/abstract/Symbol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/FatBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/FatBinary.h
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/MachoBinary.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/MachoBinary.h
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/Swap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/macho/Swap.h
)

# Enable c++11 on the target.
set_target_properties(
    binary
    PROPERTIES 
    COMPILE_FLAGS "-std=c++11"
)

# Set target specific include directories.
target_include_directories(
    binary
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/utilities
)