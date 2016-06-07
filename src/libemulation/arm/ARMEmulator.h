/*
 * ARMEmulator.h
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */

#ifndef SRC_LIBEMULATION_ARM_ARMEMULATOR_H_
#define SRC_LIBEMULATION_ARM_ARMEMULATOR_H_

#include "arm/ARMArch.h"
#include "arm/ARMContext.h"
#include "arm/ARMDisassembler.h"
#include "arm/gen/ARMInterpreter.h"
#include "memory/Memory.h"

namespace Emulator {
	class ARMEmulator {
	private:
		ARMMode m_mode;
		ARMContext &m_contex;
		ARMInterpreter m_interpreter;
		Disassembler::ARMDisassembler m_dis;
		Memory::AbstractMemory &m_memory;

	public:
		ARMEmulator(ARMContext &context, Memory::AbstractMemory &memory, ARMMode mode = ARMMode_ARM, ARMVariants = ARMv7);
		virtual ~ARMEmulator();

		void start(unsigned count = 0);

		ARMContext &getContext() const {
			return m_contex;
		}

		void setContext(ARMContext context) {
			m_contex = context;
		}

		void setMode(ARMMode mode) {
			m_mode = mode;
		}
	};
}

#endif /* SRC_LIBEMULATION_ARM_ARMEMULATOR_H_ */
