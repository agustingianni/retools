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

    auto regions = debugger.memory_regions();
    if (!regions) {
        printf("Could not get memory regions\n");
        return false;
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

    std::string library_path = "/usr/lib/libdarm.so";
    if (!debugger.library_load(library_path)) {
        printf("Could not load library\n");
        return -1;
    }

    if (!debugger.library_unload(library_path)) {
        printf("Could not unload library\n");
        return -1;
    }

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
