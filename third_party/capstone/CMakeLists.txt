set(TARGET_NAME target_capstone)
set(CAPSTONE_GIT_URL "https://github.com/aquynh/capstone.git" CACHE STRING "URL to the capstone lib repo")
ExternalProject_Add(
    ${TARGET_NAME}
    GIT_REPOSITORY    ${CAPSTONE_GIT_URL}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ./make.sh
    INSTALL_COMMAND   DESTDIR=<INSTALL_DIR> ./make.sh install
    BUILD_IN_SOURCE   1
    INSTALL_DIR       "package"
    GIT_SHALLOW       1
)

# Retrieve the installation directory path.
ExternalProject_get_property(${TARGET_NAME} INSTALL_DIR)

# Create variables pointing to the needed lib and include directories.
if(APPLE)
set(CAPSTONE_LIBRARIES_DIR "${INSTALL_DIR}/usr/local/lib")
set(CAPSTONE_INCLUDES_DIR "${INSTALL_DIR}/usr/local/include")
else()
set(CAPSTONE_LIBRARIES_DIR "${INSTALL_DIR}/usr/lib")
set(CAPSTONE_INCLUDES_DIR "${INSTALL_DIR}/usr/include")
endif()

# Create the directories.
file(MAKE_DIRECTORY "${CAPSTONE_LIBRARIES_DIR}")
file(MAKE_DIRECTORY "${CAPSTONE_INCLUDES_DIR}")

# Library names.
set(CAPSTONE_STATIC_LIBRARY_NAME "${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(CAPSTONE_SHARED_LIBRARY_NAME "${CMAKE_SHARED_LIBRARY_PREFIX}capstone${CMAKE_SHARED_LIBRARY_SUFFIX}")

# Library paths.
set(CAPSTONE_STATIC_LIBRARY_PATH "${CAPSTONE_LIBRARIES_DIR}/${CAPSTONE_STATIC_LIBRARY_NAME}")
set(CAPSTONE_SHARED_LIBRARY_PATH "${CAPSTONE_LIBRARIES_DIR}/${CAPSTONE_SHARED_LIBRARY_NAME}")

message(STATUS "capstone installation details:")
message(STATUS "  Include files  = ${CAPSTONE_INCLUDES_DIR}")
message(STATUS "  Library files  = ${CAPSTONE_LIBRARIES_DIR}")
message(STATUS "  Static library = ${CAPSTONE_STATIC_LIBRARY_NAME}")
message(STATUS "  Shared library = ${CAPSTONE_SHARED_LIBRARY_NAME}")

# Create an imported target so we can use the external project as a dependency.
add_library(capstone SHARED IMPORTED GLOBAL)
set_target_properties(capstone PROPERTIES IMPORTED_IMPLIB               ${CAPSTONE_STATIC_LIBRARY_PATH})
set_target_properties(capstone PROPERTIES IMPORTED_LOCATION             ${CAPSTONE_SHARED_LIBRARY_PATH})
set_target_properties(capstone PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CAPSTONE_INCLUDES_DIR})
add_dependencies(capstone ${TARGET_NAME})