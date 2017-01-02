/*
 * dis.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include "arm/ARMDisassembler.h"

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

    uint32_t opcode = std::stoul(arg_opcode, nullptr, 16);

    ARMMode mode = ARMMode_ARM;
    if (arg_mode == "thumb") {
        mode = ARMMode_Thumb;
        cout << "Using mode THUMB" << endl;

        if (opcode > 0xffff) {
            opcode = (opcode >> 16) | ((opcode << 16) & 0xffffffff);
        }
    }

    ARMDisassembler dis { ARMv7All };
    ARMInstruction ins = dis.disassemble(opcode, mode);
    cout << "Disassembled instruction: " << (void *) opcode << " -> " << ins.toString() << endl;

    return 0;
}
