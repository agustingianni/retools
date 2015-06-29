/*
 * ARMDisassembler.cpp
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#include "arm/ARMDisassembler.h"
#include "arm/ARMUtilities.h"
#include "arm/gen/ARMDecodingTable.h"
#include "Utilities.h"

#include <functional>
#include <iostream>

using namespace std;
using namespace Disassembler;

namespace Disassembler {
	ARMDisassembler::ARMDisassembler(ARMVariants variant) :
			m_variant(variant) {
		m_decoder = new ARMDecoder(m_variant);
	}

	std::shared_ptr<ARMInstruction> ARMDisassembler::disassemble(uint32_t op_code, ARMMode mode) {
		// // Unconditional instructions.
		// if (opcode & 0xf0000000 == 0xf0000000) {
		// 	// If the cond field is 0b1111, the instruction can only be
		// 	// executed unconditionally, see Unconditional instructions
		// 	// on page A5-214.
		// 	// Includes Advanced SIMD instructions, see Chapter A7
		// 	// Advanced SIMD and Floating-point Instruction Encoding.

		// }

	 //    if ((instr & 0x0c000000) == 0x0c000000) {
	 //        disassemble_coprocessor_instr(instr, cond_name, cond);
	 //    }

	 //    if (buf_pos == 0) {
	 //        if      (cond == 15)                         disassemble_unconditional_instr((uint32_t)addr, instr);
	 //        else if ((instr & 0x0c000000) == 0x00000000) disassemble_misc_instr(instr, cond_name);
	 //        else if ((instr & 0x0e000010) == 0x06000010) disassemble_media_instr(instr, cond_name);
	 //        else if ((instr & 0x0c000000) == 0x04000000) disassemble_load_store_instr(instr, cond_name);
	 //        else if ((instr & 0x0c000000) == 0x08000000) disassemble_branch_and_block_data_transfer((uint32_t)addr, instr, cond_name);
	 //        else if ((instr & 0x0c000000) == 0x0c000000) disassemble_supervisor_and_ext_load_store(instr, cond_name);
	 //    }

	 //    if (buf_pos == 0 && (instr & 0x0c000000) == 0x00000000) {
	 //        disassemble_data_instr(instr, cond_name);
	 //    }

		return m_decoder->decode(op_code, mode);
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
