/*
 * cli_emulator.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include "arm/ARMArch.h"
#include "arm/ARMEmulator.h"
#include "arm/ARMDisassembler.h"
#include "memory/Memory.h"

#include <memory>
#include <string>
#include <cstdint>
#include <iostream>

using namespace std;
using namespace Memory;
using namespace Register;
using namespace Emulator;
using namespace Disassembler;

int main(int argc, char **argv) {
	if (argc < 2) {
		cerr << "Usage: ./%s [thumb|arm] <hex_opcode>" << endl;
		return -1;
	}

	string arg_mode { argv[1] };

	ARMMode mode { ARMMode_ARM };
	if (arg_mode == "thumb") {
		mode = ARMMode_Thumb;
	}

	cout << "Using mode " << (mode == ARMMode_Thumb ? "THUMB" : "ARM") << endl;

	// Create a concrete memory map.
	ConcreteMemory memory { };
	if (!memory.map(0xcafe0000, 0x1000, 0)) {
		cerr << "Failed mapping address." << endl;
		return -1;
	}

	// Set some values.
	uintptr_t address = 0xcafe0000;

	address += memory.write_value(address, 0xe3a02010); // mov r2, #16
	address += memory.write_value(address, 0xe1a0100f); // mov r1, pc
	address += memory.write_value(address, 0xe2811018); // add r1, r1, #24
	address += memory.write_value(address, 0xe3a00001); // mov r0, #1
	address += memory.write_value(address, 0xe3a07004); // mov r7, #4

	// Create an execution context.
	ARMContext context { };
	context.setRegister(ARM_REG_R0, 0);
	context.setRegister(ARM_REG_PC, 0xcafe0000);

	// Create an emulator and link the memory and context
	ARMEmulator emu { context, memory };
	emu.setMode(mode);
	emu.start(5);

	return 0;
}
