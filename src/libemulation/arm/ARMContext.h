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

template<class T> const T& Max(const T& a, const T& b) { return (a < b) ? b : a; }
template<class T> const T& Min(const T& a, const T& b) { return (a < b) ? a : b; }
template<class T> const T& FPMax(const T& a, const T& b, bool val) { return (a < b) ? b : a; }
template<class T> const T& FPMin(const T& a, const T& b, bool val) { return (a < b) ? a : b; }

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

	// Processor property query routines.
	bool BadMode(unsigned mode);
	bool CurrentModeIsNotUser();
	bool CurrentModeIsUserOrSystem();
	bool CurrentModeIsHyp();
	bool HaveSecurityExt();
	bool IsSecure();
	bool HaveVirtExt();
	bool BigEndian();
	bool UnalignedSupport();
	bool HasVirtExt();
	bool HaveLPAE();
	bool IntegerZeroDivideTrappingEnabled();
	bool JazelleAcceptsExecution();
	bool HaveMPExt();

	// Debug event generation.
	void BKPTInstrDebugEvent();
	void BreakpointDebugEvent();
	void VectorCatchDebugEvent();
	void WatchpointDebugEvent();

	// Supervisor and hypervisor event generation.
	void CallHypervisor(unsigned immediate);
	void CallSupervisor(unsigned immediate);

	// Exception generators.
	void GenerateAlignmentException();
	void GenerateCoprocessorException();
	void GenerateIntegerZeroDivide();

	// Hints to the processor.
	void Hint_Debug(unsigned op);
	void Hint_PreloadData(unsigned address);
	void Hint_PreloadDataForWrite(unsigned address);
	void Hint_PreloadInstr(unsigned address);
	void Hint_Yield();

	// Current instruction accessors.
	unsigned ThisInstr();
	unsigned ThisInstrLength();

	// Barriers.
	void DataMemoryBarrier(MBReqDomain domain, MBReqTypes types);
	void DataSynchronizationBarrier(MBReqDomain domain, MBReqTypes types);
	void InstructionSynchronizationBarrier();
	void VFPExcBarrier();

    void LoadWritePC(unsigned address) {
        if (ArchVersion() >= ARMv5) {
            BXWritePC(address);
        } else {
            BranchWritePC(address);
        }
    }

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

	// This function returns the major version number of the architecture.
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

    // Processor special registers / status variables.
    apsr_t APSR;
    cpsr_t CPSR;
    fpscr_t FPSCR;
    hcr_t HCR;
    hstr_t HSTR;
    itstate_t ITSTATE;
    jmcr_t JMCR;
    nsacr_t NSACR;
    scr_t SCR;
    spsr_t SPSR;
    spsr_t SPSR_abt;
    spsr_t SPSR_fiq;
    spsr_t SPSR_hyp;
    spsr_t SPSR_irq;
    spsr_t SPSR_mon;
    spsr_t SPSR_svc;
    spsr_t SPSR_und;
    unsigned ELR_hyp = 0;

    // Configurable flags that specify the characteristics of the processor.
    bool m_has_security_extension = false;
    bool m_has_virtual_extensions = false;
    bool m_is_big_endian = false;
    bool m_supports_unaligned = false;
    bool m_have_lpae = false;
    bool m_int_zero_div_trap_enabled = false;
    bool m_jazelle_accepts_execution = false;
    bool m_have_mp_extensions = false;

    // Registers.
    std::array<uint32_t, Register::ARM_REG_CORE_MAX> m_core_regs;
    std::array<uint32_t, Register::ARM_REG_COPROC_MAX> m_coproc_regs;
    std::array<uint32_t, Register::ARM_REG_SINGLE_MAX> m_single_regs;
    std::array<uint64_t, Register::ARM_REG_DOUBLE_MAX> m_double_regs;
    std::array<uint64_t, Register::ARM_REG_QUAD_MAX> m_quad_regs;
};

#endif /* SRC_LIBDISASSEMBLY_ARM_ARMCONTEXT_H_ */
