/*
 * ARMContext.h
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_
#define SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_

#include <cstdint>

class ARMContext {
public:
	ARMContext();
	virtual ~ARMContext();

	uint32_t readRegularRegister(unsigned regno);
	uint32_t readRmode(unsigned regno);
	uint32_t readSingleRegister(unsigned regno);
	uint64_t readDoubleRegister(unsigned regno);
	uint64_t readQuadRegister(unsigned regno);

	uint32_t readMemory();
	uint32_t writeRegularRegister();
	uint32_t writeRmode();
	uint32_t writeSingleRegister();
	uint32_t writeDoubleRegister();
	uint32_t writeQuadRegister();
	uint32_t writeMemory();
	uint32_t readElement();
	uint32_t writeElement();

	void ALUWritePC(uint32_t address) {
		return;
	}

	// Return the value of PC used when storing, this may be +4 or +8.
	uint32_t PCStoreValue() {
		return readRegularRegister(15);
	}

	void BranchWritePC(uint32_t address) {
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
};

#endif /* SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_ */
