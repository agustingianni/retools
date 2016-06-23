/*
 * ARMContext.cpp
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */
#include "ARMContext.h"
#include "debug.h"

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

bool ARMContext::CurrentModeIsNotUser() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 16)
        return false; // User mode

    return true;
}

bool ARMContext::CurrentModeIsUserOrSystem() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 16)
        return true;

    if (CPSR.M == 31)
        return true;

    return false;
}

bool ARMContext::CurrentModeIsHyp() {
    if (BadMode(CPSR.M))
        UNPREDICTABLE();

    if (CPSR.M == 26)
        return true;

    return false;
}

bool ARMContext::HaveSecurityExt() {
    return m_has_security_extension;
}

bool ARMContext::IsSecure() {
    return !HaveSecurityExt() || SCR.NS == 0 || CPSR.M == 22; // Monitor mode
}

bool ARMContext::HaveVirtExt() {
    return m_has_virtual_extensions;
}
