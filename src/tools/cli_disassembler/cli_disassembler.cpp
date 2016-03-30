/*
 * dis.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include "arm/ARMDisassembler.h"

#include <memory>
#include <string>
#include <cstdint>
#include <iostream>

using namespace std;
using namespace Disassembler;

int main(int argc, char **argv) {
    if (argc < 2) {
        cerr << "Usage: ./%s [thumb|arm] <hex_opcode>" << endl;
        return -1;
    }

    string arg_mode { argv[1] };
    string arg_opcode { argv[2] };

    ARMMode mode = (arg_mode == "thumb") ? ARMMode_Thumb : ARMMode_ARM;
    uint32_t opcode = std::stoul(arg_opcode, nullptr, 16);

    ARMDisassembler dis;
    shared_ptr<ARMInstruction> ins = dis.disassemble(opcode, mode);
    cout << "Disassembled instruction: " << (void *) opcode << " -> " << ins->toString() << endl;

    return 0;
}
