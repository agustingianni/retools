#include <iostream>
#include <libdebug/Debugger.h>
#include <string>

using namespace std;
using namespace lldb;

int main(int argc, char** argv)
{
    if (argc < 1) {
        cerr << "Usage: ./%s binary_file" << endl;
        return -1;
    }

    string binary_file{ argv[1] };

    Debugger debugger{};
    debugger.disable_aslr();
    debugger.stop_at_entrypoint();
    debugger.process_execute(binary_file);

#if defined(DEBUG_LLDB)
// Enable lldb's internal debug log channel.
debugger.enable_debug_log("lldb", { "api", "break", "module", "platform", "process" });
#endif

    auto regions = debugger.memory_regions();
    if (!regions) {
        printf("Could not get memory regions\n");
        return -1;
    }

    for (auto i = 0; i < regions->GetSize(); i++) {
        SBMemoryRegionInfo info;
        if (!regions->GetMemoryRegionAtIndex(i, info))
            continue;

        printf("Name: %s mapped=%3s %c%c%c 0x%p 0x%p\n",
            info.GetName() ? info.GetName() : "no-name",
            info.IsMapped() ? "yes" : "no",
            info.IsReadable() ? 'R' : '-',
            info.IsWritable() ? 'W' : '-',
            info.IsExecutable() ? 'X' : '-',
            (void*)info.GetRegionBase(),
            (void*)info.GetRegionEnd());
    }

    printf("Dumping modules\n");
    auto modules_or_error = debugger.modules_get();
    if (!modules_or_error) {
        printf("Error while getting list of modules\n");
        return -1;
    }

    for (auto &module : *modules_or_error) {
        SBStream out;
        module.GetDescription(out);
        printf("Module: %s\n", out.GetData());
    }

    printf("Dumping instructions from PC=0x%.16llx\n", *debugger.get_pc());

    auto target = debugger.get_target();
    for (auto i = 0; i < 128; i++) {
        auto ins = *debugger.instruction_get();
        std::string comment = ins.GetComment(target);
        if (!comment.empty()) {
            comment = "; " + comment;
        }

        printf("0x%.16llx: %-8s %-40s %s\n",
            ins.GetAddress().GetLoadAddress(target),
            ins.GetMnemonic(target),
            ins.GetOperands(target),
            comment.c_str());

        if (ins.DoesBranch()) {
            puts("----------------------------------------------------------------------");
        }

        debugger.step_instruction();
    }

    std::string memory_map = "(void *) mmap(nullptr, 4096, 0x1, 0x1000 | 0x0001, 0, 0)";
    if (auto memory = debugger.evaluate_expression<void*>(memory_map)) {
        printf("Mapped memory at %p\n", *memory);
    }

    auto ret = debugger.evaluate_expression<unsigned>("(unsigned) 1+1");
    if (ret) {
        printf("Test: %u\n", *ret);
    }

    ret = debugger.evaluate_expression<unsigned>("(unsigned) getpid()");
    if (ret) {
        printf("Test: %u\n", *ret);
    }

    std::string library_path = "/usr/local/lib/libunicorn.dylib";
    if (!debugger.library_load(library_path)) {
        printf("Could not load library\n");
        return -1;
    }

    printf("Loaded library\n");

    if (!debugger.library_unload(library_path)) {
        printf("Could not unload library\n");
        return -1;
    }

    printf("Unloaded library\n");

    debugger.registers_set({
        { "rax", "0x44444444" },
        { "rbx", "0x88888888" }
    });

    if (auto reg_value = debugger.register_get("rax")) {
        printf("Register value: name=%s value=%s\n", reg_value->GetName(), reg_value->GetValue());
    }

    if (auto reg_value = debugger.register_get("rbx")) {
        printf("Register value: name=%s value=%s\n", reg_value->GetName(), reg_value->GetValue());
    }

    return 0;
}
