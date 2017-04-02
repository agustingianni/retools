set(LLDB_GIT_REPO "http://llvm.org/git/lldb.git")
set(LLDB_SOURCES_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lldb")

# Clone lldb sources if they don't exist.
if (NOT EXISTS ${LLDB_SOURCES_PATH})
    message("-- Cloning lldb's sources, this may take a while ...")
    execute_process(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        COMMAND git clone ${LLDB_GIT_REPO}
        OUTPUT_QUIET
    )
endif()

# Create a target so we can add it as a dependency.
add_custom_target(
    target_lldb_includes
    COMMAND git pull
    WORKING_DIRECTORY ${LLDB_SOURCES_PATH}
)
