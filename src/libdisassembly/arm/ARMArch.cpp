/*
 * ARMArch.cpp
 *
 *  Created on: Nov 1, 2015
 *      Author: anon
 */

#include "arm/ARMArch.h"
#include "Utilities.h"

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

bool ITSession::InITBlock() const{
	return ITCounter != 0;
}

bool ITSession::LastInITBlock() const{
	return ITCounter == 1;
}

uint32_t ITSession::GetCond() const{
	if (InITBlock())
		return get_bits(ITState, 7, 4);
	else
		return COND_AL;
}

std::string Register::name(Register::Core regno) {
    const static std::string names[] {
        "ARM_REG_R0",
        "ARM_REG_R1",
        "ARM_REG_R2",
        "ARM_REG_R3",
        "ARM_REG_R4",
        "ARM_REG_R5",
        "ARM_REG_R6",
        "ARM_REG_R7",
        "ARM_REG_R8",
        "ARM_REG_R9",
        "ARM_REG_R10",
        "ARM_REG_R11",
        "ARM_REG_R12",
        "ARM_REG_R13",
        "ARM_REG_R14",
        "ARM_REG_R15",
        "ARM_REG_CORE_MAX"
    };

    return names[static_cast<unsigned>(regno)];
}

std::string Register::name(Register::Coproc regno) {
    const static std::string names[] {
        "ARM_REG_CR0",
        "ARM_REG_CR1",
        "ARM_REG_CR2",
        "ARM_REG_CR3",
        "ARM_REG_CR4",
        "ARM_REG_CR5",
        "ARM_REG_CR6",
        "ARM_REG_CR7",
        "ARM_REG_CR8",
        "ARM_REG_CR9",
        "ARM_REG_CR10",
        "ARM_REG_CR11",
        "ARM_REG_CR12",
        "ARM_REG_CR13",
        "ARM_REG_CR14",
        "ARM_REG_CR15",
        "ARM_REG_COPROC_MAX"
    };

    return names[static_cast<unsigned>(regno)];
}

std::string Register::name(Register::Double regno) {
    const static std::string names[] {
        "ARM_REG_D0",
        "ARM_REG_D1",
        "ARM_REG_D2",
        "ARM_REG_D3",
        "ARM_REG_D4",
        "ARM_REG_D5",
        "ARM_REG_D6",
        "ARM_REG_D7",
        "ARM_REG_D8",
        "ARM_REG_D9",
        "ARM_REG_D10",
        "ARM_REG_D11",
        "ARM_REG_D12",
        "ARM_REG_D13",
        "ARM_REG_D14",
        "ARM_REG_D15",
        "ARM_REG_D16",
        "ARM_REG_D17",
        "ARM_REG_D18",
        "ARM_REG_D19",
        "ARM_REG_D20",
        "ARM_REG_D21",
        "ARM_REG_D22",
        "ARM_REG_D23",
        "ARM_REG_D24",
        "ARM_REG_D25",
        "ARM_REG_D26",
        "ARM_REG_D27",
        "ARM_REG_D28",
        "ARM_REG_D29",
        "ARM_REG_D30",
        "ARM_REG_D31",
        "ARM_REG_DOUBLE_MAX"
    };

    return names[static_cast<unsigned>(regno)];
}

std::string Register::name(Register::Quad regno) {
    const static std::string names[] {
        "ARM_REG_Q0",
        "ARM_REG_Q1",
        "ARM_REG_Q2",
        "ARM_REG_Q3",
        "ARM_REG_Q4",
        "ARM_REG_Q5",
        "ARM_REG_Q6",
        "ARM_REG_Q7",
        "ARM_REG_Q8",
        "ARM_REG_Q9",
        "ARM_REG_Q10",
        "ARM_REG_Q11",
        "ARM_REG_Q12",
        "ARM_REG_Q13",
        "ARM_REG_Q14",
        "ARM_REG_Q15",
        "ARM_REG_QUAD_MAX"
    };

    return names[static_cast<unsigned>(regno)];
}

std::string Register::name(Register::Single regno) {
    const static std::string names[] {
        "ARM_REG_S0",
        "ARM_REG_S1",
        "ARM_REG_S2",
        "ARM_REG_S3",
        "ARM_REG_S4",
        "ARM_REG_S5",
        "ARM_REG_S6",
        "ARM_REG_S7",
        "ARM_REG_S8",
        "ARM_REG_S9",
        "ARM_REG_S10",
        "ARM_REG_S11",
        "ARM_REG_S12",
        "ARM_REG_S13",
        "ARM_REG_S14",
        "ARM_REG_S15",
        "ARM_REG_S16",
        "ARM_REG_S17",
        "ARM_REG_S18",
        "ARM_REG_S19",
        "ARM_REG_S20",
        "ARM_REG_S21",
        "ARM_REG_S22",
        "ARM_REG_S23",
        "ARM_REG_S24",
        "ARM_REG_S25",
        "ARM_REG_S26",
        "ARM_REG_S27",
        "ARM_REG_S28",
        "ARM_REG_S29",
        "ARM_REG_S30",
        "ARM_REG_S31",
        "ARM_REG_SINGLE_MAX"
    };

    return names[static_cast<unsigned>(regno)];
}

std::ostream &operator<<(std::ostream& os, Register::Core regno) {
    os << Register::name(regno);
    return os;
}

std::ostream &operator<<(std::ostream& os, Register::Coproc regno) {
    os << Register::name(regno);
    return os;
}

std::ostream &operator<<(std::ostream& os, Register::Double regno) {
    os << Register::name(regno);
    return os;
}

std::ostream &operator<<(std::ostream& os, Register::Quad regno) {
    os << Register::name(regno);
    return os;
}

std::ostream &operator<<(std::ostream& os, Register::Single regno) {
    os << Register::name(regno);
    return os;
}
