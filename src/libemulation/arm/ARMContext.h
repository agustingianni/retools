/*
 * ARMContext.h
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_
#define SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_

#include "arm/ARMArch.h"
#include <cstdint>

class ARMContext {
public:
	ARMContext();
	virtual ~ARMContext();

	uint32_t readRegularRegister(unsigned regno);
	uint32_t readRmode(unsigned regno, unsigned n);
	uint32_t readSingleRegister(unsigned regno);
	uint64_t readDoubleRegister(unsigned regno);
	uint64_t readQuadRegister(unsigned regno);

	uint32_t readMemory(uintptr_t address, unsigned size);
	uint32_t writeRegularRegister(unsigned regno, uintptr_t value);
	uint32_t writeRmode(unsigned regno, unsigned size, uintptr_t value);
	uint32_t writeSingleRegister(unsigned regno, float value);
	uint32_t writeDoubleRegister(unsigned regno, double value);
	uint32_t writeQuadRegister(unsigned regno, uint64_t value);
	uint32_t writeMemory(uintptr_t address, unsigned size, uintptr_t value);
	uint32_t readElement(uintptr_t address, uintptr_t value, unsigned size);
	uint32_t writeElement(uintptr_t address, unsigned size, uintptr_t value);

	void ALUWritePC(uint32_t address) {
		return;
	}

	// Return the value of PC used when storing, this may be +4 or +8.
	uint32_t PCStoreValue() {
		return readRegularRegister(15);
	}

	ARMMode CurrentInstrSet() {
	    return m_opcode_mode;
	}

	bool IsZero(unsigned i) {
		return i == 0;
	}

	bool InITBlock() {
	    return CurrentInstrSet() == InstrSet_Thumb && m_it_session.InITBlock();
	}

	bool LastInITBlock() {
	    return CurrentInstrSet() == InstrSet_Thumb && m_it_session.LastInITBlock();
	}

	bool CurrentModeIsHyp() {
		return m_hyp_mode;
	}

	ARMVariants ArchVersion() {
		return m_arm_isa;
	}

	// TODO: Implement.
	void BranchTo(uintptr_t address) {
		return;
	}

	void UNPREDICTABLE() {
		return;
	}

	void BranchWritePC(uintptr_t address) {
		if (CurrentInstrSet() == InstrSet_ARM) {
			if (ArchVersion() < 6 && (address & 3) != 0) {
				UNPREDICTABLE();
			}

			BranchTo(address & 0xfffffffc);
		} else if (CurrentInstrSet() == InstrSet_Jazelle) {
			BranchTo(address);
		} else {
			BranchTo(address & 1);
		}
	}

private:
    bool m_hyp_mode;
    ITSession m_it_session;
    ARMMode m_opcode_mode;
    ARMVariants m_arm_isa;
    apsr_t APSR;
    fpscr_t FPSCR;
};

#endif /* SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_ */
