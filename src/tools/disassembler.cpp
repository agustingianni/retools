/*
 * dis.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include "arm/ARMDisassembler.h"

#include <memory>
#include <iostream>

using namespace std;
using namespace Disassembler;

int main(int argc, char **argv) {
	ARMDisassembler dis;
	uint32_t opcode = 0xe92d4ff0;
	shared_ptr<ARMInstruction> ins = dis.disassemble(opcode, ARMMode_Thumb);
	cout << "Disassembled instruction: " << (void *) opcode << " -> "
			<< ins->toString() << endl;

	return 0;
}
