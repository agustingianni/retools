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
