/*
 * ARMDisassembler.cpp
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#include "ARMDisassembler.h"
#include "ARMUtilities.h"
#include "utilities/Utilities.h"

#include <functional>
#include <iostream>

using namespace std;
using namespace Disassembler;

namespace Disassembler {
	ARMDisassembler::ARMDisassembler() {
	}

	ARMDisassembler::~ARMDisassembler() {
	}

	deque<Instruction> ARMDisassembler::disassemble(vector<uint8_t> buffer) {
		return deque<Instruction>();
	}

} /* namespace Disassembler */
