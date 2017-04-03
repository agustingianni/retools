#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include <map>
#include <string>
#include <vector>

#include <Conditionals.h>
#include <lldb/API/LLDB.h>
#include <optional.h>

#if RETOOLS_TARGET_CPU_X86
static constexpr auto ARCH_GENERIC_STACK_POINTER = "esp";
static constexpr auto ARCH_GENERIC_FRAME_POINTER = "ebp";
#elif RETOOLS_TARGET_CPU_AMD64
static constexpr auto ARCH_GENERIC_STACK_POINTER = "rsp";
static constexpr auto ARCH_GENERIC_FRAME_POINTER = "rbp";
#elif RETOOLS_TARGET_CPU_ARM
static constexpr auto ARCH_GENERIC_STACK_POINTER = "sp";
static constexpr auto ARCH_GENERIC_FRAME_POINTER = "bp";
#elif RETOOLS_TARGET_CPU_ARM64
static constexpr auto ARCH_GENERIC_STACK_POINTER = "sp";
static constexpr auto ARCH_GENERIC_FRAME_POINTER = "bp";
#else
#error Invalid architecture
#endif

class Debugger {
private:
    lldb::SBDebugger m_debugger;
    lldb::SBTarget m_target;
    lldb::SBProcess m_process;
    lldb::SBThread m_thread;

    // Loaded binary file data.
    lldb::SBModule m_module;

    int m_launch_flags;

    std::map<std::string, uint32_t> m_libmap;

public:
    Debugger();
    ~Debugger();

    // Delete copy and other stuff.
    Debugger(const Debugger& other) = delete;
    Debugger(Debugger&& other) = delete;
    Debugger& operator=(const Debugger&) = delete;
    Debugger& operator=(Debugger&&) = delete;

    lldb::SBDebugger& get_debugger()
    {
        return m_debugger;
    }

    lldb::SBTarget& get_target()
    {
        return m_target;
    }

    lldb::SBProcess& get_process()
    {
        return m_process;
    }

    lldb::SBThread& get_thread()
    {
        return m_thread;
    }

    lldb::SBModule& get_module()
    {
        return m_module;
    }

    void disable_aslr()
    {
        m_launch_flags |= lldb::eLaunchFlagDisableASLR;
    }

    void stop_at_entrypoint()
    {
        m_launch_flags |= lldb::eLaunchFlagStopAtEntry;
    }

    // Utilities to alter the behavior of the remote process.
    bool library_load(std::string filename);
    bool library_unload(std::string filename);

    // Process execution.
    bool process_execute(std::string filename);
    bool process_execute(std::string filename, std::vector<std::string> args);
    bool process_execute(std::string filename, std::vector<std::string> args, std::vector<std::string> env);
    bool process_execute(std::string filename, std::vector<std::string> args, std::vector<std::string> env, std::string cwd);

    // Attach and detach routines.
    bool process_attach(std::string process_name, bool wait = false);
    bool process_attach(lldb::pid_t pid);
    bool process_detach();

    // Main process related utilities.
    bool process_continue();
    bool process_kill();
    bool process_stop();

    // Breakpoint handling.
    std::optional<lldb::SBBreakpoint> breakpoint_add(uintptr_t address);
    std::optional<lldb::SBBreakpoint> breakpoint_add(std::string function_name, std::string module_name = {});
    bool breakpoint_del(lldb::SBBreakpoint& breakpoint);

    // Perform actions on all breakpoints.
    bool breakpoint_delete_all();
    bool breakpoint_enable_all();
    bool breakpoint_disable_all();

    // Breakpoint saving / loading.
    bool breakpoint_save(std::string filename);
    bool breakpoint_load(std::string filename);

    // Data breakpoints access breakpoints.
    std::optional<lldb::SBWatchpoint> watchpoint_add(uintptr_t address, size_t size, bool read = true, bool write = true);
    bool watchpoint_del(lldb::SBWatchpoint& breakpoint);

    // Perform actions on all data breakpoints.
    bool watchpoint_delete_all();
    bool watchpoint_enable_all();
    bool watchpoint_disable_all();

    // Typed memory operations.
    template <typename T>
    bool memory_read(uintptr_t address, T* value);

    template <typename T>
    bool memory_write(uintptr_t address, T value);

    template <typename T>
    bool memory_write(uintptr_t address, T value, size_t count);

    // Raw memory operations.
    bool memory_read(uintptr_t address, void* buffer, size_t size);
    bool memory_write(uintptr_t address, const void* buffer, size_t size);

    // Stepping functions for the current thread.
    bool step_out();
    bool step_instruction(bool step_over = false);
    bool step_to(uintptr_t address);

    // Stepping functions for 'thread'.
    bool step_out(lldb::SBThread& thread);
    bool step_instruction(lldb::SBThread& thread, bool step_over = false);
    bool step_to(lldb::SBThread& thread, uintptr_t address);

    // Multiple register access routines.
    std::optional<lldb::SBValueList> registers_get();
    std::optional<lldb::SBValueList> registers_get(lldb::SBThread& thread);

    bool registers_set(std::map<std::string, std::string> values);
    bool registers_set(lldb::SBThread& thread, std::map<std::string, std::string> values);

    // Single register access routines.
    std::optional<lldb::SBValue> register_get(std::string register_name);
    std::optional<lldb::SBValue> register_get(lldb::SBThread& thread, std::string register_name);

    bool register_set(std::string register_name, std::string register_value);
    bool register_set(lldb::SBThread& thread, std::string register_name, std::string register_value);

    // Getters for special purpose registers. Returns the value or empty if failed.
    std::optional<uintptr_t> get_fp();
    std::optional<uintptr_t> get_fp(lldb::SBThread& thread);
    std::optional<uintptr_t> get_pc();
    std::optional<uintptr_t> get_pc(lldb::SBThread& thread);
    std::optional<uintptr_t> get_sp();
    std::optional<uintptr_t> get_sp(lldb::SBThread& thread);

    // Setters for special purpose registers. Returns the old value or empty if failed.
    std::optional<uintptr_t> set_fp(uintptr_t address);
    std::optional<uintptr_t> set_fp(lldb::SBThread& thread, uintptr_t address);
    std::optional<uintptr_t> set_pc(uintptr_t address);
    std::optional<uintptr_t> set_pc(lldb::SBThread& thread, uintptr_t address);
    std::optional<uintptr_t> set_sp(uintptr_t address);
    std::optional<uintptr_t> set_sp(lldb::SBThread& thread, uintptr_t address);

    // Methods to work with the stack.
    template <typename T>
    bool stack_push(T value);

    template <typename T>
    bool stack_push(lldb::SBThread& thread, T value);

    template <typename T>
    bool stack_pop(T* value);

    template <typename T>
    bool stack_pop(lldb::SBThread& thread, T* value);
};

#endif /* DEBUGGER_H_ */
