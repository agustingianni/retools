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

	static uint32_t CountITSize(uint32_t ITMask) {
		uint32_t TZ = __builtin_ctz(ITMask);
		if (TZ > 3) {
			return 0;
		}

		return (4 - TZ);
	}

	bool ITSession::InitIT(uint32_t bits7_0) {
		ITCounter = CountITSize(get_bits(bits7_0, 3, 0));
		if (ITCounter == 0)
			return false;

		unsigned short FirstCond = get_bits(bits7_0, 7, 4);
		if (FirstCond == 0xF) {
			return false;
		}

		if (FirstCond == 0xE && ITCounter != 1) {
			return false;
		}

		ITState = bits7_0;
		return true;
	}

	void ITSession::ITAdvance() {
		--ITCounter;
		if (ITCounter == 0)
			ITState = 0;
		else {
			unsigned short NewITState4_0 = get_bits(ITState, 4, 0) << 1;
			// SetBits32(ITState, 4, 0, NewITState4_0);
			ITState = (ITState & 0xffffffe0) | NewITState4_0;
		}
	}

	bool ITSession::InITBlock() {
		return ITCounter != 0;
	}

	bool ITSession::LastInITBlock() {
		return ITCounter == 1;
	}

	uint32_t ITSession::GetCond() {
		if (InITBlock())
			return get_bits(ITState, 7, 4);
		else
			return COND_AL;
	}
} /* namespace Disassembler */
