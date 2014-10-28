/*
 * ARMDisassembler.cpp
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#include "ARMDisassembler.h"

#include <functional>

using namespace std;

namespace Disassembler {

	const ARMOpcode ARMDisassembler::arm_opcodes[] = { { 0xfbe08000, 0xf1400000, ARMv6T2 | ARMv7, eEncodingT1, No_VFP,
			eSize32, decode_adc_immediate } };

	bool ARMDisassembler::decode_adc_immediate(uint32_t opcode, ARMEncoding encoding) {
		return true;
	}

	ARMDisassembler::ARMDisassembler() {
	}

	ARMDisassembler::~ARMDisassembler() {
	}

	// 32[ sf 0 0 100111 N 0 Rm(5) imms(6) Rn(5) Rd(5)

	deque<Instruction> ARMDisassembler::disassemble(vector<uint8_t> buffer) {
		return deque<Instruction>();
	}

} /* namespace Disassembler */
