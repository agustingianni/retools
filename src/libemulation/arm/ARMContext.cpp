/*
 * ARMContext.cpp
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */
#include "ARMContext.h"
#include "debug.h"
#include "Utilities.h"

#include <cassert>

template<typename T> const T& Max(const T& a, const T& b) {
    return (a < b) ? b : a;
}

template<typename T> const T& Min(const T& a, const T& b) {
    return (a < b) ? a : b;
}

template<typename T> const T& FPMax(const T& a, const T& b, bool val) {
    return (a < b) ? b : a;
}

template<typename T> const T& FPMin(const T& a, const T& b, bool val) {
    return (a < b) ? a : b;
}

template<typename T> T RoundDown(T val) {
    return floor(val);
}

template<typename T> T RoundUp(T val) {
    return ceil(val);
}

template<typename T> T RoundTowardsZero(T val) {
    if (val == 0.0) {
        return 0.0;
    } else if (val > 0.0) {
        return RoundDown(val);
    } else {
        return RoundUp(val);
    }
}

template<typename T> T FPNeg(T operand) {
    return -operand;
}

template<typename T> T FPAbs(T operand) {
    return fabs(operand);
}

template<typename T> T FPZero(unsigned sign, unsigned N) {
    return sign ? -0.0 : 0.0;
}

template<typename T> T FPTwo(unsigned N) {
    return 2.0;
}

template<typename T> T FPThree(unsigned N) {
    return 3.0;
}

template<typename T> T FPMaxNormal(unsigned sign, unsigned N) {
    assert("Not implemented");
}

template<typename T> T FPInfinity(unsigned sign, unsigned N) {
    return (sign ? -1 : 1) * std::numeric_limits<T>::infinity();
}

template<typename T> T FPDefaultNaN(unsigned N) {
    return std::numeric_limits<T>::quiet_NaN();
}

void UNDEFINED() {
    LOG_ABORT("Rached an UNDEFINED instruction.");
}

void UNPREDICTABLE() {
    LOG_ABORT("Rached an UNPREDICTABLE instruction.");
}

void AlignmentFault(uint32_t address, bool iswrite) {
    LOG_ABORT("%s alignment fault at 0x%.8x.", iswrite ? "Write" : "Read", address);
}

ARMContext::ARMContext(Memory::AbstractMemory &memory) :
        m_memory { memory } {
    for (auto i = 0; i < Register::ARM_REG_CORE_MAX; i++)
        m_core_regs[i] = 0;

    for (auto i = 0; i < Register::ARM_REG_COPROC_MAX; i++)
        m_coproc_regs[i] = 0;

    for (auto i = 0; i < Register::ARM_REG_SINGLE_MAX; i++)
        m_single_regs[i] = 0;

    for (auto i = 0; i < Register::ARM_REG_DOUBLE_MAX; i++)
        m_double_regs[i] = 0;

    for (auto i = 0; i < Register::ARM_REG_QUAD_MAX; i++)
        m_quad_regs[i] = 0;
}

ARMContext::~ARMContext() {
}

#include <cstdio>

void ARMContext::dump() {
    LOG_DEBUG("ARMContext:");
    LOG_DEBUG(" r0 = 0x%.8x  r1 = 0x%.8x  r2 = 0x%.8x  r3 = 0x%.8x  r4 = 0x%.8x  r5 = 0x%.8x  r6 = 0x%.8x  r7 = 0x%.8x",
            m_core_regs[0], m_core_regs[1], m_core_regs[2], m_core_regs[3],
            m_core_regs[4], m_core_regs[5], m_core_regs[6], m_core_regs[7]
    );

    LOG_DEBUG(" r8 = 0x%.8x  r9 = 0x%.8x r10 = 0x%.8x r11 = 0x%.8x r12 = 0x%.8x r13 = 0x%.8x r14 = 0x%.8x r15 = 0x%.8x",
            m_core_regs[8], m_core_regs[9], m_core_regs[10], m_core_regs[11],
            m_core_regs[12], m_core_regs[13], m_core_regs[14], m_core_regs[15]
    );
}

void ARMContext::setRegister(Register::Core reg, uint32_t value) {
    LOG_DEBUG("reg=%s, value=0x%.8x", Register::name(reg).c_str(), value);
    m_core_regs[reg] = value;
}

void ARMContext::getRegister(Register::Core reg, uint32_t &value) {
    LOG_DEBUG("reg=%s", Register::name(reg).c_str());
    value = m_core_regs[reg];
}

void ARMContext::setRegister(Register::Coproc reg, uint32_t value) {
    LOG_DEBUG("reg=%s, value=0x%.8x", Register::name(reg).c_str(), value);
    m_coproc_regs[reg] = value;
}

void ARMContext::getRegister(Register::Coproc reg, uint32_t &value) {
    LOG_DEBUG("reg=%s", Register::name(reg).c_str());
    value = m_coproc_regs[reg];
}

void ARMContext::setRegister(Register::Single reg, uint32_t value) {
    LOG_DEBUG("reg=%s, value=0x%.8x", Register::name(reg).c_str(), value);
    m_single_regs[reg] = value;
}

void ARMContext::getRegister(Register::Single reg, uint32_t &value) {
    LOG_DEBUG("reg=%s", Register::name(reg).c_str());
    value = m_single_regs[reg];
}

void ARMContext::setRegister(Register::Double reg, uint64_t value) {
    LOG_DEBUG("reg=%s, value=0x%.8x", Register::name(reg).c_str(), value);
    m_double_regs[reg] = value;
}

void ARMContext::getRegister(Register::Double reg, uint64_t &value) {
    LOG_DEBUG("reg=%s", Register::name(reg).c_str());
    value = m_double_regs[reg];
}

void ARMContext::setRegister(Register::Quad reg, uint64_t value) {
    LOG_DEBUG("reg=%s, value=0x%.8x", Register::name(reg).c_str(), value);
    m_quad_regs[reg] = value;
}

void ARMContext::getRegister(Register::Quad reg, uint64_t &value) {
    LOG_DEBUG("reg=%s", Register::name(reg).c_str());
    value = m_quad_regs[reg];
}

uint32_t ARMContext::readRegularRegister(unsigned regno) {
    uint32_t value;
    getRegister(static_cast<Register::Core>(regno), value);
    return value;
}

uint32_t ARMContext::readRmode(unsigned regno, unsigned n) {
    return 0;
}

uint32_t ARMContext::readSingleRegister(unsigned regno) {
    uint32_t value;
    getRegister(static_cast<Register::Single>(regno), value);
    return value;
}

uint64_t ARMContext::readDoubleRegister(unsigned regno) {
    uint64_t value;
    getRegister(static_cast<Register::Double>(regno), value);
    return value;
}

uint64_t ARMContext::readQuadRegister(unsigned regno) {
    uint64_t value;
    getRegister(static_cast<Register::Quad>(regno), value);
    return value;
}

void ARMContext::writeRegularRegister(unsigned regno, uintptr_t value) {
    setRegister(static_cast<Register::Core>(regno), value);
}

void ARMContext::writeRmode(unsigned regno, unsigned size, uintptr_t value) {
    setRegister(static_cast<Register::Core>(regno), value);
}

void ARMContext::writeSingleRegister(unsigned regno, float value) {
    setRegister(static_cast<Register::Single>(regno), value);
}

void ARMContext::writeDoubleRegister(unsigned regno, double value) {
    setRegister(static_cast<Register::Double>(regno), value);
}

void ARMContext::writeQuadRegister(unsigned regno, uint64_t value) {
    setRegister(static_cast<Register::Quad>(regno), value);
}

uint32_t ARMContext::read_MemA(uintptr_t address, unsigned size) {
    return read_MemA_with_priv(address, size, CurrentModeIsNotUser());
}

uint32_t ARMContext::read_MemA_unpriv(uintptr_t address, unsigned size) {
    return read_MemA_with_priv(address, size, false);
}

uint32_t ARMContext::read_MemA_with_priv(uintptr_t address, unsigned size, bool privileged) {
    if (address != Align(address, size)) {
        if (SCTLR.A && SCTLR.U) {
            AlignmentFault(address, false);
        }

        address = Align(address, size);
    }

    uint32_t value = readMemory(address, size);
    if (CPSR.E) {
        BigEndianReverse(value, size);
    }

    return value;
}

uint32_t ARMContext::read_MemU(uintptr_t address, unsigned size) {
    return read_MemU_with_priv(address, size, CurrentModeIsNotUser());
}

uint32_t ARMContext::read_MemU_unpriv(uintptr_t address, unsigned size) {
    return read_MemU_with_priv(address, size, false);
}

uint32_t ARMContext::read_MemU_with_priv(uintptr_t address, unsigned size, bool privileged) {
    if (SCTLR.A == 0 && SCTLR.U == 0) {
        address = Align(address, size);
    }

    uint32_t value;
    if (address == Align(address, size)) {
        value = read_MemA_with_priv(address, size, privileged);
    } else if (SCTLR.A) {
        AlignmentFault(address, false);
    } else {
        for (unsigned i = 0; i < size; i++) {
            reinterpret_cast<uint8_t *>(&value)[i] = read_MemA_with_priv(address + i, 1, privileged);
        }

        if (CPSR.E) {
            BigEndianReverse(value, size);
        }
    }

    return value;
}

void ARMContext::write_MemA(uint32_t value, uintptr_t address, unsigned size) {
    write_MemA_with_priv(value, address, size, CurrentModeIsNotUser());

}

void ARMContext::write_MemA_unpriv(uint32_t value, uintptr_t address, unsigned size) {
    write_MemA_with_priv(value, address, size, false);
}

void ARMContext::write_MemA_with_priv(uint32_t value, uintptr_t address, unsigned size, bool privileged) {
    if (address != Align(address, size)) {
        if (SCTLR.A && SCTLR.U) {
            AlignmentFault(address, false);
        }

        address = Align(address, size);
    }

    if (CPSR.E) {
        BigEndianReverse(value, size);
    }

    writeMemory(address, size, value);
}

void ARMContext::write_MemU(uint32_t value, uintptr_t address, unsigned size) {
    return write_MemU_with_priv(value, address, size, CurrentModeIsNotUser());
}

void ARMContext::write_MemU_unpriv(uint32_t value, uintptr_t address, unsigned size) {
    return write_MemU_with_priv(value, address, size, false);
}

void ARMContext::write_MemU_with_priv(uint32_t value, uintptr_t address, unsigned size, bool privileged) {
    if (SCTLR.A == 0 && SCTLR.U == 0) {
        address = Align(address, size);
    }

    if (address == Align(address, size)) {
        write_MemA_with_priv(value, address, size, privileged);
    } else if (SCTLR.A) {
        AlignmentFault(address, true);
    } else {
        if (CPSR.E) {
            BigEndianReverse(value, size);
        }

        for (unsigned i = 0; i < size; i++) {
            write_MemA_with_priv(reinterpret_cast<uint8_t *>(&value)[i], address + i, 1, privileged);
        }
    }
}

uint32_t ARMContext::readMemory(uintptr_t address, unsigned size) {
    LOG_DEBUG("address=0x%.8x, size=0x%.8x", address, size);
    uint64_t value = 0;
    m_memory.read(address, &value, size);
    return value;
}

uint32_t ARMContext::writeMemory(uintptr_t address, unsigned size, uintptr_t value) {
    LOG_DEBUG("address=0x%.8x, size=0x%.8x, value=0x%.8x", address, size, value);
    return 0;
}

uint32_t ARMContext::readElement(uintptr_t address, uintptr_t value, unsigned size) {
    LOG_DEBUG("address=0x%.8x, value=0x%.8x, size=0x%.8x", address, value, size);
    return 0;
}

uint32_t ARMContext::writeElement(uintptr_t address, unsigned size, uintptr_t value, unsigned what) {
    LOG_DEBUG("address=0x%.8x, size=0x%.8x, value=0x%.8x, what=0x%.8x", address, size, value, what);
    return 0;
}

// The BadMode() function tests whether a 5-bit mode number corresponds to one of the permitted modes:
bool ARMContext::BadMode(unsigned mode) {
    bool result;

    switch (mode) {
    case 16: // 10000
    case 17: // 10001
    case 18: // 10010
    case 19: // 10011
        result = false;
        break;
    case 22: // 10110
        result = !HaveSecurityExt();
        break;
    case 23: // 10111
        break;
    case 26: // 11010
        result = !HaveVirtExt();
        break;
    case 27: // 11011
    case 31: // 11111
        result = false;
        break;
    default:
        result = true;
    }

    return result;
}

// Returns TRUE if current mode executes at PL1 or higher.
bool ARMContext::CurrentModeIsNotUser() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 16)
        return false; // User mode

    return true;
}

// Returns TRUE if current mode is User or System mode.
bool ARMContext::CurrentModeIsUserOrSystem() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 16)
        return true;

    if (CPSR.M == 31)
        return true;

    return false;
}

// Returns TRUE if current mode is Hyp mode
bool ARMContext::CurrentModeIsHyp() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 26)
        return true;

    return false;
}

// The HaveSecurityExt() function returns TRUE if the implementation includes the Security Extensions, and FALSE otherwise.
bool ARMContext::HaveSecurityExt() {
    return m_has_security_extension;
}

// The IsSecure() function returns TRUE if the processor is in Secure state, or if the
// implementation does not include the Security Extensions, and FALSE otherwise.
bool ARMContext::IsSecure() {
    return !HaveSecurityExt() || SCR.NS == 0 || CPSR.M == 22; // Monitor mode
}

// This function returns TRUE if the implementation includes the Virtualization Extensions.
bool ARMContext::HaveVirtExt() {
    return m_has_virtual_extensions;
}

// This function returns TRUE if ENDIANSTATE == 1.
bool ARMContext::BigEndian() {
    return m_is_big_endian;
}

// This function returns TRUE if the processor currently provides support for unaligned memory accesses,
// or FALSE otherwise. This is always TRUE in ARMv7, controllable by the SCTLR.U bit in ARMv6, and always
// FALSE before ARMv6.
bool ARMContext::UnalignedSupport() {
    return m_supports_unaligned;
}

// This function returns TRUE if the implementation includes the Virtualization Extensions.
bool ARMContext::HasVirtExt() {
    return m_has_virtual_extensions;
}

// This function returns TRUE if the implementation includes the Large Physical Address Extension.
bool ARMContext::HaveLPAE() {
    return m_have_lpae;
}

// This function returns TRUE if the trapping of divisions by zero in the integer division
// instructions SDIV and UDIV is enabled, and FALSE otherwise.
// In the ARMv7-R profile, this is controlled by the SCTLR.DZ bit. The ARMv7-A profile does
// not support trapping of integer division by zero.
bool ARMContext::IntegerZeroDivideTrappingEnabled() {
    return m_int_zero_div_trap_enabled;
}

// This function indicates whether Jazelle hardware will take over execution when a BXJ instruction is executed.
bool ARMContext::JazelleAcceptsExecution() {
    return m_jazelle_accepts_execution;
}

// This function returns TRUE if the implementation includes the Multiprocessing Extensions.
bool ARMContext::HaveMPExt() {
    return m_have_mp_extensions;
}

// Create a BKPT instruction debug event.
void ARMContext::BKPTInstrDebugEvent() {
    assert("Method not implemented.");
}

// Create a breakpoint debug event.
void ARMContext::BreakpointDebugEvent() {
    assert("Method not implemented.");
}

// Create a vector catch debug event.
void ARMContext::VectorCatchDebugEvent() {
    assert("Method not implemented.");
}

// Create a watcpoint debug event.
void ARMContext::WatchpointDebugEvent()  {
    assert("Method not implemented.");
}

// Generate an exception for HVC instruction
void ARMContext::CallHypervisor(unsigned immediate) {
    assert("Method not implemented.");
}

// Generate an exception for SVC instruction
void ARMContext::CallSupervisor(unsigned immediate) {
    assert("Method not implemented.");
}

// Generate an exception for a failed address alignment check.
void ARMContext::GenerateAlignmentException() {
    assert("Method not implemented.");
}

// Generate the exception for an unclaimed coprocessor instruction.
void ARMContext::GenerateCoprocessorException() {
    assert("Method not implemented.");
}

// Generate the exception for a trapped divide-by-zero for an integer divide instruction.
void ARMContext::GenerateIntegerZeroDivide() {
    assert("Method not implemented.");
}

// This procedure supplies a hint to the debug system.
void ARMContext::Hint_Debug(unsigned op) {
    LOG_DEBUG("Debug hint!");
}

// This procedure performs a preload data hint.
void ARMContext::Hint_PreloadData(unsigned address) {
    LOG_DEBUG("Preload data at 0x%.8x hint!", address);
}

// This procedure performs a preload data hint with a probability that the use will be for a write.
void ARMContext::Hint_PreloadDataForWrite(unsigned address) {
    LOG_DEBUG("Preload data for write at 0x%.8x hint!", address);
}

// This procedure performs a preload instructions hint.
void ARMContext::Hint_PreloadInstr(unsigned address) {
    LOG_DEBUG("Preload instruction at 0x%.8x hint!", address);
}

// This procedure performs a Yield hint.
void ARMContext::Hint_Yield() {
    LOG_DEBUG("Yield hint!");
}

// This function returns the bitstring encoding of the currently-executing instruction.
unsigned ARMContext::ThisInstr() {
    assert("Method not implemented.");
}

// This function returns the length, in bits, of the current instruction. This means it returns 32 or 16.
unsigned ARMContext::ThisInstrLength() {
    assert("Method not implemented.");
}

// Perform a Data Memory Barrier operation.
void ARMContext::DataMemoryBarrier(MBReqDomain domain, MBReqTypes types) {
    LOG_DEBUG("Data memory barrier!");
}

// Perform a Data Synchronization Barrier operation.
void ARMContext::DataSynchronizationBarrier(MBReqDomain domain, MBReqTypes types) {
    LOG_DEBUG("Data synchronization barrier!");
}

// Perform an Instruction Synchronization operation.
void ARMContext::InstructionSynchronizationBarrier() {
    LOG_DEBUG("Instruction synchronization barrier!");
}

// Ensure all outstanding Floating-point Extension exception processing have occurred.
void ARMContext::VFPExcBarrier() {
    LOG_DEBUG("VFP Extension barrier!");
}

bool ARMContext::EventRegistered() {
    return m_event_register;
}

void ARMContext::ClearEventRegister() {
    m_event_register = 0;
}

void ARMContext::SendEvent() {
    m_event_register = 1;
}

void ARMContext::WaitForEvent() {
    while(!m_event_register) {
    }
}

void ARMContext::SwitchToJazelleExecution() {
    assert("Method not implemented.");
}

bool ARMContext::ExclusiveMonitorsPass(unsigned address, unsigned size) {
    assert("Not implemented");
}

void ARMContext::ClearExclusiveLocal(unsigned processorid) {
    assert("Not implemented");
}

void ARMContext::SerializeVFP() {
    assert("Not implemented");
}

void ARMContext::SetExclusiveMonitors(unsigned address, unsigned size) {
    assert("Not implemented");
}

// Suspends execution until a WFI wake-up event or reset occurs.
void ARMContext::WaitForInterrupt() {
    assert("Not implemented");
}

// This function returns an integer that uniquely identifies the executing processor in the system.
unsigned ARMContext::ProcessorID() {
    assert("Not implemented");
}

// Get word from coprocessor, for an MRC or MRC2 instruction.
unsigned ARMContext::Coproc_GetOneWord(unsigned cp_num, unsigned instr) {
    assert("Not implemented");
    return 0;
}

// Get two words from coprocessor, for an MRRC or MRRC2 instruction.
std::tuple<unsigned, unsigned> ARMContext::Coproc_GetTwoWords(unsigned cp_num, unsigned instr) {
    assert("Not implemented");
    return std::tuple<unsigned, unsigned>(0, 0);
}

// Get next word to store from coprocessor, for STC or STC2 instruction.
unsigned ARMContext::Coproc_GetWordToStore(unsigned cp_num, unsigned instr) {
    assert("Not implemented");
    return 0;
}

// Instruct coprocessor to perform an internal operation, for a CDP or CDP2 instruction.
void ARMContext::Coproc_InternalOperation(unsigned cp_num, unsigned instr) {
    assert("Not implemented");
}

// Send next loaded word to coprocessor, for LDC or LDC2 instruction.
void ARMContext::Coproc_SendLoadedWord(unsigned word, unsigned cp_num, unsigned instr) {
    assert("Not implemented");
}

// Send word to coprocessor, for an MCR or MCR2 instruction.
void ARMContext::Coproc_SendOneWord(unsigned word, unsigned cp_num, unsigned instr) {
    assert("Not implemented");
}

// Send two words to coprocessor, for an MCRR or MCRR2 instruction
void ARMContext::Coproc_SendTwoWords(unsigned word2, unsigned word1, unsigned cp_num, unsigned instr) {
    assert("Not implemented");
}

// Determines whether the coprocessor instruction is accepted.
bool ARMContext::Coproc_Accepted(unsigned cp_num, unsigned instr) {
    return true;
}

// Returns TRUE if enough words have been loaded, for an LDC or LDC2 instruction.
bool ARMContext::Coproc_DoneLoading(unsigned cp_num, unsigned instr) {
    return true;
}

// Returns TRUE if enough words have been stored, for an STC or STC2 instruction.
bool ARMContext::Coproc_DoneStoring(unsigned cp_num, unsigned instr) {
    return true;
}

uint32_t ARMContext::CurrentCond() {
    assert("Method not implemented.");
    return 0;
}

// Returns TRUE if the current instruction passes its condition code check.
bool ARMContext::ConditionPassed() {
    uint32_t cond = CurrentCond();
    bool result = false;

    // Evaluate base condition.
    switch (get_bits(cond, 3, 1)) {
        case 0:
            result = (APSR.Z == 1);
            break;
        case 1:
            result = (APSR.C == 1);
            break;
        case 2:
            result = (APSR.N == 1);
            break;
        case 3:
            result = (APSR.V == 1);
            break;
        case 4:
            result = (APSR.C == 1) && (APSR.Z == 0);
            break;
        case 5:
            result = (APSR.N == APSR.V);
            break;
        case 6:
            result = (APSR.N == APSR.V) && (APSR.Z == 0);
            break;
        case 7:
            result = true;
            break;
    }

    // Condition flag values in the set '111x' indicate the instruction is always executed.
    // Otherwise, invert condition if necessary.
    if (get_bit(cond, 0) == 1 && cond != 15)
        result = !result;

    return result;
}

// Performs entry to Monitor mode.
void ARMContext::EnterMonitorMode(uint32_t new_spsr_value, uint32_t new_lr_value, int vect_offset) {
    CPSR.M = 22;
    SPSR = new_spsr_value;
    setRegister(Register::Core::ARM_REG_LR, new_lr_value);
    CPSR.J = 0;
    CPSR.T = SCTLR.TE;
    CPSR.E = SCTLR.EE;
    CPSR.A = 1;
    CPSR.F = 1;
    CPSR.I = 1;
    CPSR.IT_1_0 = CPSR.IT_7_2 = 0;
    BranchTo(MVBAR + vect_offset);
}

// Performs entry to Hyp mode.
void ARMContext::EnterHypMode(uint32_t new_spsr_value, uint32_t preferred_exceptn_return, int vect_offset) {
    CPSR.M = 26;
    SPSR = new_spsr_value;
    ELR_hyp = preferred_exceptn_return;
    CPSR.J = 0;
    CPSR.T = HSCTLR.TE;
    CPSR.E = HSCTLR.EE;

    if (SCR.EA == 0)
        CPSR.A = 1;

    if (SCR.FIQ == 0)
        CPSR.F = 1;

    if (SCR.IRQ == 0)
        CPSR.I = 1;

    CPSR.IT_1_0 = CPSR.IT_7_2 = 0;
    BranchTo(HVBAR + vect_offset);
}

void ARMContext::TakeHypTrapException() {
    uint32_t preferred_exceptn_return = PC() - ((CPSR.T == 1) ? 4 : 8);
    uint32_t new_spsr_value = CPSR;
    EnterHypMode(new_spsr_value, preferred_exceptn_return, 20);
}

void ARMContext::TakeSMCException() {
    m_it_session.ITAdvance();
    uint32_t new_lr_value = (CPSR.T == 1) ? PC() : (PC() - 4);
    uint32_t new_spsr_value = CPSR;
    uint32_t vect_offset = 8;
    if (CPSR.M == 2)
        SCR.NS = 0;

    EnterMonitorMode(new_spsr_value, new_lr_value, vect_offset);
}

// Writes a syndrome into the HSR.
void ARMContext::WriteHSR(unsigned ec, unsigned HSRString) {
    uint32_t HSRValue = 0;
    set_bits(HSRValue, 31, 26, ec);

    if (get_bits(ec, 5, 3) != 4 || (get_bit(ec, 2) == 1 && get_bit(HSRString, 24) == 1)) {
        set_bit(HSRValue, 25, (ThisInstrLength() == 32) ? 1 : 0);
    }

    if (get_bits(ec, 5, 4) == 0 && get_bits(ec, 3, 0) != 0) {
        if (CurrentInstrSet() == InstrSet_ARM) {
            set_bit(HSRValue, 24, 1);
            set_bits(HSRValue, 23, 20, CurrentCond());
        } else {
            set_bit(HSRValue, 24, IMPLEMENTATION_DEFINED);
            if (get_bit(HSRValue, 24) == 1) {
                // IMPLEMENTATION_DEFINED choice between CurrentCond() and '1110'
                if (ConditionPassed()) {
                    set_bits(HSRValue, 23, 20, IMPLEMENTATION_DEFINED);
                } else {
                    set_bits(HSRValue, 23, 20, CurrentCond());
                }
            }
        }
        set_bits(HSRValue, 19, 0, get_bits(HSRString, 19, 0));
    } else {
        set_bits(HSRValue, 24, 0, HSRString);
    }

    HSR = HSRValue;
}

// Checks for MRS (Banked register) or MSR (Banked register) accesses to registers
// other than the SPSRs that are invalid. This includes ELR_hyp accesses.
void ARMContext::BankedRegisterAccessValid(unsigned SYSm, unsigned mode) {
    if (get_bits(SYSm, 4, 3) == 0)
        if (get_bits(SYSm, 2, 0) == 7) {
            UNPREDICTABLE();
        } else if (get_bits(SYSm, 2, 0) == 6) {
            if (mode == 26 || mode == 31)
                UNPREDICTABLE();
        } else if (get_bits(SYSm, 2, 0) == 5) {
            if (mode == 31)
                UNPREDICTABLE();
        } else if (mode != 17) {
            UNPREDICTABLE();
        }

        else if (get_bits(SYSm, 4, 3) == 1) {
            if (get_bits(SYSm, 2, 0) == 7 || mode == 17 || (NSACR.RFR == 1 && !IsSecure()))
                UNPREDICTABLE();
        }

        else if (get_bits(SYSm, 4, 3) == 3) {
            if (get_bit(SYSm, 2) == 0) {
                UNPREDICTABLE();
            } else if (get_bit(SYSm, 1) == 0) {
                if (!IsSecure() || mode == 22)
                    UNPREDICTABLE();
            } else {
                if (mode != 22)
                    UNPREDICTABLE();
            }
        }
}

void ARMContext::CPSRWriteByInstr(unsigned value, unsigned byte_mask, bool is_exception_return) {
    bool privileged = CurrentModeIsNotUser();
    bool nmfi = SCTLR.NMFI == 1;

    if (get_bit(byte_mask, 3) == 1) {
        set_bits(CPSR, 31, 27, get_bits(value, 31, 27));
        if (is_exception_return) {
            set_bits(CPSR, 26, 24, get_bits(value, 26, 24));
        }
    }

    if (get_bit(byte_mask, 2) == 1) {
        set_bits(CPSR, 19, 16, get_bits(value, 19, 16));
    }

    if (get_bit(byte_mask, 1) == 1) {
        if (is_exception_return) {
            set_bits(CPSR, 15, 10, get_bits(value, 15, 10));
        }

        set_bit(CPSR, 9, get_bit(value, 9));
        if (privileged && (IsSecure() || SCR.AW == 1 || HaveVirtExt())) {
            set_bit(CPSR, 8, get_bit(value, 8));
        }
    }

    if (get_bit(byte_mask, 0) == 1) {
        if (privileged) {
            set_bit(CPSR, 7, get_bit(value, 7));
        }

        if (privileged && (!nmfi || get_bit(value, 6) == 0) && (IsSecure() || SCR.FW == 1 || HaveVirtExt())) {
            set_bit(CPSR, 6, get_bit(value, 6));
        }

        if (is_exception_return) {
            set_bit(CPSR, 5, get_bit(value, 5));
        }

        if (privileged) {
            if (BadMode(get_bits(value, 4, 0))) {
                UNPREDICTABLE();
            }

            if (!IsSecure() && get_bits(value, 4, 0) == 22)
                UNPREDICTABLE();

            if (!IsSecure() && get_bits(value, 4, 0) == 17 && NSACR.RFR == 1)
                UNPREDICTABLE();

            if (SCR.NS == 0 && get_bits(value, 4, 0) == 26)
                UNPREDICTABLE();

            if (!IsSecure() && CPSR.M != 26 && get_bits(value, 4, 0) == 26)
                UNPREDICTABLE();

            if (CPSR.M == 26 && get_bits(value, 4, 0) != 26 && !is_exception_return)
                UNPREDICTABLE();

            CPSR.M = get_bits(value, 4, 0);
        }
    }
}

// Undefined Instruction exception if the specified one of the Advanced SIMD and Floating-point Extensions is not enabled.
void ARMContext::CheckAdvSIMDOrVFPEnabled(bool include_fpexc_check, bool advsimd) {
    // In Non-secure state, Non-secure view of CPACR and HCPTR determines behavior // Copy register values
    unsigned cpacr_cp10 = CPACR.cp10;
    unsigned cpacr_cp11 = CPACR.cp11;
    unsigned cpacr_asedis = CPACR.ASEDIS;

    unsigned hcptr_cp10;
    unsigned hcptr_cp11;
    unsigned hcptr_tase;

    if (HaveVirtExt()) {
        hcptr_cp10 = HCPTR.TCP10;
        hcptr_cp11 = HCPTR.TCP11;
        hcptr_tase = HCPTR.TASE;
    }

    if (HaveSecurityExt()) {
        // Check Non-Secure Access Control Register for permission to use CP10/11.
        if (NSACR.cp10 != NSACR.cp11)
            UNPREDICTABLE();

        if (!IsSecure()) {
            // Modify register values to the Non-secure view
            if (NSACR.cp10 == 0) {
                cpacr_cp10 = 0;
                cpacr_cp11 = 0;

                if (HaveVirtExt()) {
                    hcptr_cp10 = 1;
                    hcptr_cp11 = 1;
                }
            }

            if (NSACR.NSASEDIS == 1) {
                cpacr_asedis = 1;

                if (HaveVirtExt()) {
                    hcptr_tase = 1;
                }
            }
        }
    }

    // Check Coprocessor Access Control Register for permission to use CP10/11.
    if (!HaveVirtExt() || !CurrentModeIsHyp()) {
        if (cpacr_cp10 != cpacr_cp11)
            UNPREDICTABLE();

        switch (cpacr_cp10) {
            case 0:
                UNDEFINED();
                break;
            case 1:
                if (!CurrentModeIsNotUser())
                    UNDEFINED();

                break;
            case 2:
                UNPREDICTABLE();
                break;
            case 3:
                break;
        }

        // If the Advanced SIMD extension is specified, check whether it is disabled.
        if (advsimd && cpacr_asedis == 1)
            UNDEFINED();
    }

    // If required, check FPEXC enabled bit.
    if (include_fpexc_check && FPEXC.EN == 0)
        UNDEFINED();

    if (HaveSecurityExt() && HaveVirtExt() && !IsSecure()) {
        if (hcptr_cp10 != hcptr_cp11)
            UNPREDICTABLE();

        if (hcptr_cp10 == 1 || (advsimd && hcptr_tase == 1)) {
            unsigned HSRString = 0;
            if (advsimd && hcptr_tase == 1) {
                set_bit(HSRString, 5, 1);
            } else {
                set_bit(HSRString, 5, 0);
                set_bits(HSRString, 3, 0, 10);
            }

            WriteHSR(7, HSRString);
            if (!CurrentModeIsHyp()) {
                TakeHypTrapException();
            } else {
                UNDEFINED();
            }
        }
    }
}

void ARMContext::CheckAdvSIMDEnabled() {
    CheckAdvSIMDOrVFPEnabled(true, true);
    m_double_regs_clone = m_double_regs;
}

void ARMContext::CheckVFPEnabled(bool include_fpexc_check) {
    CheckAdvSIMDOrVFPEnabled(include_fpexc_check, false);
}

// A null check is performed for all load/store instructions when they are executed in ThumbEE state.
// If the value in the base register is zero, execution branches to the NullCheck handler at HandlerBase – 4.
void ARMContext::NullCheckIfThumbEE(unsigned n) {
    if (CurrentInstrSet() == InstrSet_ThumbEE) {
        if (n == 15) {
            if (IsZero(Align(PC(), 4)))
                UNPREDICTABLE();
        } else if (n == 13) {
            if (IsZero (SP()))
                UNPREDICTABLE();
        } else {
            if (IsZero (readRegularRegister(n))) {
                // PC holds this instruction's address plus 4 ITSTATE.IT = '00000000';
                LR((PC() & 0xfffffffe) | 1);
                BranchWritePC(TEEHBR - 4);
            }
        }
    }
}

// SPSR[] - non-assignment form
uint32_t &ARMContext::SPSR_() {
    if (BadMode(CPSR.M)) {
        UNPREDICTABLE();
    }

    switch (CPSR.M) {
        case 17:
            // FIQ mode
            return SPSR_fiq;
        case 18:
            // IRQ mode
            return SPSR_irq;
        case 19:
            // Supervisor mode
            return SPSR_svc;
        case 22:
            // Monitor mode
            return SPSR_mon;
        case 23:
            // Abort mode
            return SPSR_abt;
        case 26:
            // Hyp mode
            return SPSR_hyp;
        case 27:
            // Undefined mode
            return SPSR_und;
        default:
            UNPREDICTABLE();
            break;
    }
}

// SPSR[] - assignment form
void ARMContext::SPSR_(uint32_t value) {
    if (BadMode(CPSR.M)) {
        UNPREDICTABLE();
    }

    switch (CPSR.M) {
        case 17:
            // FIQ mode
            SPSR_fiq = value;
            break;
        case 18:
            // IRQ mode
            SPSR_irq = value;
            break;
        case 19:
            // Supervisor mode
            SPSR_svc = value;
            break;
        case 22:
            // Monitor mode
            SPSR_mon = value;
            break;
        case 23:
            // Abort mode
            SPSR_abt = value;
            break;
        case 26:
            // Hyp mode
            SPSR_hyp = value;
            break;
        case 27:
            // Undefined mode
            SPSR_und = value;
            break;
        default:
            UNPREDICTABLE();
            break;
    }
}

// SPSR write by an instruction
void ARMContext::SPSRWriteByInstr(unsigned value, unsigned bytemask) {
    if (CurrentModeIsUserOrSystem())
        UNPREDICTABLE();

    // N,Z,C,V,Q flags, IT<1:0>,J execution state bits
    if (get_bit(bytemask, 3) == 1)
        set_bits(SPSR, 31, 24, get_bits(value, 31, 24));

    // bits <23:20> are reserved SBZP bits
    if (get_bit(bytemask, 2) == 1)
        set_bits(SPSR, 19, 16, get_bits(value, 19, 16));

    // IT<7:2> execution state bits, E bit, A interrupt mask
    if (get_bit(bytemask, 1) == 1)
        set_bits(SPSR, 15, 8, get_bits(value, 15, 8));

    if (get_bit(bytemask, 0) == 1) {
        // I,F interrupt masks, T execution state bit
        set_bits(SPSR, 7, 5, get_bits(value, 7, 5));
        if (BadMode(get_bits(value, 4, 0)))
            UNPREDICTABLE();
        else
            set_bits(SPSR, 4, 0, get_bits(value, 4, 0));
    }
}

// Checks for MRS or MSR accesses to the Banked SPSRs that are UNPREDICTABLE
void ARMContext::SPSRaccessValid(unsigned SYSm, unsigned mode) {
    switch (SYSm) {
        case 14:
            if ((!IsSecure() && NSACR.RFR == 1) || mode == 17)
                UNPREDICTABLE();
            break;
        case 16:
            if (mode == 18)
                UNPREDICTABLE();
            break;
        case 18:
            if (mode == 19)
                UNPREDICTABLE();
            break;
        case 20:
            if (mode == 23)
                UNPREDICTABLE();
            break;
        case 22:
            if (mode == 27)
                UNPREDICTABLE();
            break;
        case 28:
            if (mode == 22 || !IsSecure())
                UNPREDICTABLE();
            break;
        case 30:
            if (mode != 22)
                UNPREDICTABLE();
            break;
        default:
            UNPREDICTABLE();
            break;
    }
}
