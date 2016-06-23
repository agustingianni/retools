/*
 * ARMContext.h
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_
#define SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_

#include "arm/ARMArch.h"
#include "memory/Memory.h"

#include <cstdint>
#include <cassert>
#include <array>

class ARMContext {
public:
	ARMContext(Memory::AbstractMemory &memory);
	virtual ~ARMContext();

	void dump();

	void setRegister(Register::Core reg, uint32_t value);
	void getRegister(Register::Core reg, uint32_t &value);
	void setRegister(Register::Coproc reg, uint32_t value);
	void getRegister(Register::Coproc reg, uint32_t &value);
	void setRegister(Register::Single reg, uint32_t value);
	void getRegister(Register::Single reg, uint32_t &value);
	void setRegister(Register::Double reg, uint64_t value);
	void getRegister(Register::Double reg, uint64_t &value);
	void setRegister(Register::Quad reg, uint64_t value);
	void getRegister(Register::Quad reg, uint64_t &value);

	uint32_t readRegularRegister(unsigned regno);
	uint32_t readRmode(unsigned regno, unsigned n);
	uint32_t readSingleRegister(unsigned regno);
	uint64_t readDoubleRegister(unsigned regno);
	uint64_t readQuadRegister(unsigned regno);

	void writeRegularRegister(unsigned regno, uintptr_t value);
	void writeRmode(unsigned regno, unsigned size, uintptr_t value);
	void writeSingleRegister(unsigned regno, float value);
	void writeDoubleRegister(unsigned regno, double value);
	void writeQuadRegister(unsigned regno, uint64_t value);

    uint32_t readMemory(uintptr_t address, unsigned size);
	uint32_t writeMemory(uintptr_t address, unsigned size, uintptr_t value);
	uint32_t readElement(uintptr_t address, uintptr_t value, unsigned size);
	uint32_t writeElement(uintptr_t address, unsigned size, uintptr_t value, unsigned what);

	void ALUWritePC(uint32_t address) {
        if (ArchVersion() >= ARMv7 && CurrentInstrSet() == InstrSet_ARM)
            BXWritePC(address);
        else
            BranchWritePC(address);

		return;
	}

    void BXWritePC(uint32_t address) {
        if (CurrentInstrSet() == InstrSet_ThumbEE) {
            if (address & 1 == 1) {
                BranchTo(address & 0xfffffffe); // Remaining in ThumbEE state
            } else {
                UNPREDICTABLE();
            }
        } else if (address & 1 == 1) {
            SelectInstrSet(InstrSet_Thumb);
            BranchTo(address & 0xfffffffe);
        } else if (address & 2 == 0) {
            SelectInstrSet(InstrSet_ARM);
            BranchTo(address);
        } else {
            UNPREDICTABLE();
        }
    }

    void SelectInstrSet(ARMMode instruction_set) {
        m_opcode_mode = instruction_set;
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

    void BranchTo(uintptr_t address) {
        setRegister(Register::ARM_REG_PC, address);
    }

	void UNPREDICTABLE() {
		assert(false && "Rached an Unpredictable instruction.");
	}

    void BranchWritePC(uintptr_t address) {
        if (CurrentInstrSet() == InstrSet_ARM) {
            if (ArchVersion() < ARMv6 && (address & 3) != 0) {
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
    Memory::AbstractMemory &m_memory;
    bool m_hyp_mode;
    ITSession m_it_session;
    ARMMode m_opcode_mode;
    ARMVariants m_arm_isa;
    apsr_t APSR;
    fpscr_t FPSCR;

    // Registers.
    std::array<uint32_t, Register::ARM_REG_CORE_MAX> m_core_regs;
    std::array<uint32_t, Register::ARM_REG_COPROC_MAX> m_coproc_regs;
    std::array<uint32_t, Register::ARM_REG_SINGLE_MAX> m_single_regs;
    std::array<uint64_t, Register::ARM_REG_DOUBLE_MAX> m_double_regs;
    std::array<uint64_t, Register::ARM_REG_QUAD_MAX> m_quad_regs;
};

#endif /* SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_ */
