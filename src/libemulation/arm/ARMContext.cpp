/*
 * ARMContext.cpp
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */
#include "ARMContext.h"
#include "debug.h"

#include <cassert>

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
