/*
 * ARMEmulator.cpp
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */

#include "debug.h"
#include "ARMEmulator.h"
#include "ARMDisassembler.h"

using namespace std;
using namespace Register;
using namespace Disassembler;

namespace Emulator {
    ARMEmulator::ARMEmulator(ARMContext *context, Memory::AbstractMemory *memory, ARMMode mode, ARMVariants variant) :
		m_mode{mode}, m_contex{context}, m_memory{memory} {
			m_dis = new ARMDisassembler(variant);
			m_interpreter = new ARMInterpreter(*m_contex);
    }

    ARMEmulator::~ARMEmulator() {
    }

    void ARMEmulator::start(unsigned count) {
    	bool stop = false;
    	unsigned n_executed = 0;

    	uint32_t cur_pc = 0;
    	uint32_t cur_opcode = 0;
    	ARMMode cur_mode = m_mode;

    	m_contex->getRegister(ARM_REG_PC, cur_pc);

		while (!stop && n_executed < count) {
		    // 1. Fetch an instruction from main memory.
			m_memory->read_value(cur_pc, cur_opcode);

			// 2. Decode it.
			ARMInstruction ins = m_dis->disassemble(cur_opcode, cur_mode);

			// 3. Execute the instruction.
			m_interpreter->execute(ins);

			// 4. Print the status of the registers.
			m_contex->dump();

			if (cur_pc == m_contex->PC()) {
				cur_pc += ins.ins_size / 8;
				m_contex->PC(cur_pc);
			}

			n_executed++;
		}
    }
}
