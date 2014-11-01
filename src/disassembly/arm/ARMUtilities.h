/*
 * ARMUtilities.h
 *
 *  Created on: Oct 31, 2014
 *      Author: anon
 */

#ifndef ARMUTILITIES_H_
#define ARMUTILITIES_H_

#include <tuple>
#include <cassert>
#include <cstdint>

#include "ARMDisassembler.h"
#include "utilities/Utilities.h"

static inline void NOP() {
}

// Implementation of: (bits(N), bit) LSL_C(bits(N) x, integer shift)
static inline uint32_t LSL_C(uint32_t x, uint32_t shift, uint32_t &carry_out) {
	carry_out = shift <= 32 ? get_bit(x, 32 - shift) : 0;
	return x << shift;
}

// Implementation of: bits(N) LSL(bits(N) x, integer shift)
static inline uint32_t LSL(uint32_t x, uint32_t shift) {
	if (shift == 0)
		return x;

	uint32_t unused;
	return LSL_C(x, shift, unused);
}

// Implementation of: (bits(N), bit) LSR_C(bits(N) x, integer shift)
static inline uint32_t LSR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
	carry_out = amount <= 32 ? get_bit(value, amount - 1) : 0;
	return value >> amount;
}

// Implementation of: bits(N) LSR(bits(N) x, integer shift)
static inline uint32_t LSR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return LSR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) ASR_C(bits(N) x, integer shift)
static inline uint32_t ASR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
	if (amount <= 32) {
		carry_out = get_bit(value, amount - 1);
		int64_t extended = SignExtend64<32>(value);
		return UnsignedBits(extended, amount + 31, amount);
	}

	bool negative = get_bit(value, 31);
	carry_out = (negative ? 1 : 0);
	return (negative ? 0xffffffff : 0);
}

// Implementation of: bits(N) ASR(bits(N) x, integer shift)
static inline uint32_t ASR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return ASR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) ROR_C(bits(N) x, integer shift)
static inline uint32_t ROR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
	if (amount == 0)
		return value;

	uint32_t amt = amount % 32;
	uint32_t result = Rotr32(value, amt);
	carry_out = get_bit(value, 31);
	return result;
}

// Implementation of: bits(N) ROR(bits(N) x, integer shift)
static inline uint32_t ROR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return ROR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) RRX_C(bits(N) x, bit carry_in)
static inline uint32_t RRX_C(uint32_t value, uint32_t carry_in, uint32_t &carry_out) {
	carry_out = get_bit(value, 0);
	return get_bit(carry_in, 0) << 31 | get_bits(value, 31, 1);
}

// Implementation of: bits(N) RRX(bits(N) x, bit carry_in)
static inline uint32_t RRX(uint32_t value, uint32_t carry_in) {
	uint32_t unused;
	return RRX_C(value, carry_in, unused);
}

// Implementation of: (SRType, integer) DecodeImmShift(bits(2) type, bits(5) imm5)
static inline std::tuple<uint32_t, uint32_t> DecodeImmShift(uint32_t type, uint32_t imm5) {
	switch (type) {
		case 0:
			return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_LSL, imm5);
		case 1:
			return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_LSR, imm5 == 0 ? 32 : imm5);
		case 2:
			return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_ASR, imm5 == 0 ? 32 : imm5);
		case 3:
			if (imm5 == 0) {
				return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_RRX, 1);
			} else {
				return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_ROR, imm5);
			}
	}

	return std::tuple<uint32_t, uint32_t>(Disassembler::SRType_Invalid, UINT32_MAX);
}

// Implementation of: SRType DecodeRegShift(bits(2) type)
static inline Disassembler::shift_t DecodeRegShift(uint32_t type) {
	switch (type) {
		default:
			return Disassembler::SRType_Invalid;
		case 0:
			return Disassembler::SRType_LSL;
		case 1:
			return Disassembler::SRType_LSR;
		case 2:
			return Disassembler::SRType_ASR;
		case 3:
			return Disassembler::SRType_ROR;
	}
}

// Implementation of: (bits(N), bit) Shift_C(bits(N) value, SRType type, integer amount, bit carry_in)
static inline uint32_t Shift_C(uint32_t value, Disassembler::shift_t type, uint32_t amount, uint32_t carry_in,
		uint32_t &carry_out) {
	assert(!(type == Disassembler::SRType_RRX && amount != 1));

	if (amount == 0) {
		carry_out = carry_in;
		return value;
	}

	uint32_t result;
	switch (type) {
		case Disassembler::SRType_LSL:
			result = LSL_C(value, amount, carry_out);
			break;
		case Disassembler::SRType_LSR:
			result = LSR_C(value, amount, carry_out);
			break;
		case Disassembler::SRType_ASR:
			result = ASR_C(value, amount, carry_out);
			break;
		case Disassembler::SRType_ROR:
			result = ROR_C(value, amount, carry_out);
			break;
		case Disassembler::SRType_RRX:
			result = RRX_C(value, carry_in, carry_out);
			break;
		default:
			assert(0 && "Invalid shift type.");
	}

	return result;
}

// Implementation of: bits(N) Shift(bits(N) value, SRType type, integer amount, bit carry_in)
static inline uint32_t Shift(uint32_t value, Disassembler::shift_t type, uint32_t amount, uint32_t carry_in) {
	uint32_t unused;
	return Shift_C(value, type, amount, carry_in, unused);
}

// Implementation of: (bits(32), bit) ARMExpandImm_C(bits(12) imm12, bit carry_in)
static inline std::tuple<uint32_t, uint32_t> ARMExpandImm_C(uint32_t imm12, uint32_t carry_in) {
	uint32_t unrotated_value = get_bits(imm12, 7, 0);
	uint32_t carry_out;
	uint32_t imm32 = Shift_C(unrotated_value, Disassembler::SRType_ROR, 2 * get_bits(imm12, 11, 8), carry_in,
			carry_out);
	return std::tuple<uint32_t, uint32_t>(imm32, carry_out);
}

// Implementation of: bits(32) ARMExpandImm(bits(12) imm12)
static inline uint32_t ARMExpandImm(uint32_t imm12) {
	// APSR.C argument to following function call does not affect the imm32 result.
	uint32_t carry_in = 0;
	return std::get<0>(ARMExpandImm_C(imm12, carry_in));
}

static uint32_t ror(uint32_t val, uint32_t N, uint32_t shift) {
	uint32_t m = shift % N;
	return (val >> m) | (val << (N - m));
}

// (imm32, carry_out) = ThumbExpandImm_C(imm12, carry_in)
static inline std::tuple<uint32_t, uint32_t> ThumbExpandImm_C(uint32_t opcode, uint32_t carry_in) {
	uint32_t imm32; // the expanded result
	uint32_t i = get_bit(opcode, 26);
	uint32_t imm3 = get_bits(opcode, 14, 12);
	uint32_t abcdefgh = get_bits(opcode, 7, 0);
	uint32_t imm12 = i << 11 | imm3 << 8 | abcdefgh;
	uint32_t carry_out = 0;

	if (get_bits(imm12, 11, 10) == 0) {
		switch (get_bits(imm12, 9, 8)) {
			default: // Keep static analyzer happy with a default case
			case 0:
				imm32 = abcdefgh;
				break;

			case 1:
				imm32 = abcdefgh << 16 | abcdefgh;
				break;

			case 2:
				imm32 = abcdefgh << 24 | abcdefgh << 8;
				break;

			case 3:
				imm32 = abcdefgh << 24 | abcdefgh << 16 | abcdefgh << 8 | abcdefgh;
				break;
		}

		carry_out = carry_in;
	} else {
		uint32_t unrotated_value = 0x80 | get_bits(imm12, 6, 0);
		imm32 = ror(unrotated_value, 32, get_bits(imm12, 11, 7));
		carry_out = get_bit(imm32, 31);
	}

	return std::tuple<uint32_t, uint32_t>(imm32, carry_out);
}

static inline uint32_t ThumbExpandImm(uint32_t opcode) {
	// 'carry_in' argument to following function call does not affect the imm32 result.
	uint32_t carry_in = 0;
	return std::get<0>(ThumbExpandImm_C(opcode, carry_in));
}

/* Generate N copies of |bit| in the bottom of a ULong. */
static uint64_t Replicate(uint64_t bit, int N) {
	assert(bit <= 1 && N >= 1 && N < 64);
	if (bit == 0) {
		return 0;
	} else {
		/* Careful.  This won't work for N == 64. */
		return (1ULL << N) - 1;
	}
}

static uint64_t Replicate32x2(uint64_t bits32) {
	assert(0 == (bits32 & ~0xFFFFFFFFULL));
	return (bits32 << 32) | bits32;
}

static uint64_t Replicate16x4(uint64_t bits16) {
	assert(0 == (bits16 & ~0xFFFFULL));
	return Replicate32x2((bits16 << 16) | bits16);
}

static uint64_t Replicate8x8(uint64_t bits8) {
	assert(0 == (bits8 & ~0xFFULL));
	return Replicate16x4((bits8 << 8) | bits8);
}

static uint64_t VFPExpandImm(uint64_t imm8, int N) {
	assert(imm8 <= 0xFF);
	assert(N == 32 || N == 64);
	int E = ((N == 32) ? 8 : 11) - 2; // The spec incorrectly omits the -2.
	int F = N - E - 1;
	uint64_t imm8_6 = (imm8 >> 6) & 1;
	/* sign: 1 bit */
	/* exp:  E bits */
	/* frac: F bits */
	uint64_t sign = (imm8 >> 7) & 1;
	uint64_t exp = ((imm8_6 ^ 1) << (E - 1)) | Replicate(imm8_6, E - 1);
	uint64_t frac = ((imm8 & 63) << (F - 6)) | Replicate(0, F - 6);
	assert(sign < (1ULL << 1));
	assert(exp < (1ULL << E));
	assert(frac < (1ULL << F));
	assert(1 + E + F == N);
	uint64_t res = (sign << (E + F)) | (exp << F) | frac;
	return res;
}

// Implementation of: bits(64) AdvSIMDExpandImm(bit op, bits(4) cmode, bits(8) imm8)
static inline uint64_t AdvSIMDExpandImm(unsigned op, unsigned cmode, unsigned imm8) {
	uint64_t imm64 = 0;
	bool testimm8 = false;

	switch (cmode >> 1) {
		case 0:
			testimm8 = false;
			imm64 = Replicate32x2(imm8);
			break;
		case 1:
			testimm8 = true;
			imm64 = Replicate32x2(imm8 << 8);
			break;
		case 2:
			testimm8 = true;
			imm64 = Replicate32x2(imm8 << 16);
			break;
		case 3:
			testimm8 = true;
			imm64 = Replicate32x2(imm8 << 24);
			break;
		case 4:
			testimm8 = false;
			imm64 = Replicate16x4(imm8);
			break;
		case 5:
			testimm8 = true;
			imm64 = Replicate16x4(imm8 << 8);
			break;
		case 6:
			testimm8 = true;
			if ((cmode & 1) == 0)
				imm64 = Replicate32x2((imm8 << 8) | 0xFF);
			else
				imm64 = Replicate32x2((imm8 << 16) | 0xFFFF);
			break;
		case 7:
			testimm8 = false;
			if ((cmode & 1) == 0 && op == 0)
				imm64 = Replicate8x8(imm8);

			if ((cmode & 1) == 0 && op == 1) {
				imm64 = 0;
				imm64 |= (imm8 & 0x80) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x40) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x20) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x10) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x08) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x04) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x02) ? 0xFF : 0x00;
				imm64 <<= 8;
				imm64 |= (imm8 & 0x01) ? 0xFF : 0x00;
			}

			if ((cmode & 1) == 1 && op == 0) {
				uint64_t imm8_7 = (imm8 >> 7) & 1;
				uint64_t imm8_6 = (imm8 >> 6) & 1;
				uint64_t imm8_50 = imm8 & 63;
				uint64_t imm32 = (imm8_7 << (1 + 5 + 6 + 19)) | ((imm8_6 ^ 1) << (5 + 6 + 19))
						| (Replicate(imm8_6, 5) << (6 + 19)) | (imm8_50 << 19);
				imm64 = Replicate32x2(imm32);
			}

			if ((cmode & 1) == 1 && op == 1) {
				// imm64 = imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,8):imm8<5:0>:Zeros(48);
				uint64_t imm8_7 = (imm8 >> 7) & 1;
				uint64_t imm8_6 = (imm8 >> 6) & 1;
				uint64_t imm8_50 = imm8 & 63;
				imm64 = (imm8_7 << 63) | ((imm8_6 ^ 1) << 62) | (Replicate(imm8_6, 8) << 54) | (imm8_50 << 48);
			}
			break;
		default:
			assert(0);
	}

	return imm64;
}

#endif /* ARMUTILITIES_H_ */
