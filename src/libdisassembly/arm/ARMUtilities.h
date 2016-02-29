/*
 * ARMUtilities.h
 *
 *  Created on: Oct 31, 2014
 *      Author: anon
 */

#ifndef ARMUTILITIES_H_
#define ARMUTILITIES_H_

#include <tuple>
#include <cstdint>
#include <cstdlib>

#include "arm/ARMDisassembler.h"
#include "arm/ARMArch.h"
#include "Utilities.h"

inline void NOP() {
}

inline bool EncodingIsARM(ARMEncoding e) {
    return e == eEncodingA1 || e == eEncodingA2 || e == eEncodingA3 || e == eEncodingA4 || e == eEncodingA5;
}

inline bool EncodingIsThumb(ARMEncoding e) {
    return e == eEncodingT1 || e == eEncodingT2 || e == eEncodingT3 || e == eEncodingT4 || e == eEncodingT5;
}

// Implementation of: (bits(N), bit) LSL_C(bits(N) x, integer shift)
inline uint32_t LSL_C(uint32_t x, uint32_t shift, uint32_t &carry_out) {
	carry_out = shift <= 32 ? get_bit(x, 32 - shift) : 0;
	return x << shift;
}

// Implementation of: bits(N) LSL(bits(N) x, integer shift)
inline uint32_t LSL(uint32_t x, uint32_t shift) {
	if (shift == 0)
		return x;

	uint32_t unused;
	return LSL_C(x, shift, unused);
}

// Implementation of: (bits(N), bit) LSR_C(bits(N) x, integer shift)
inline uint32_t LSR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
	carry_out = amount <= 32 ? get_bit(value, amount - 1) : 0;
	return value >> amount;
}

// Implementation of: bits(N) LSR(bits(N) x, integer shift)
inline uint32_t LSR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return LSR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) ASR_C(bits(N) x, integer shift)
inline uint32_t ASR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
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
inline uint32_t ASR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return ASR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) ROR_C(bits(N) x, integer shift)
inline uint32_t ROR_C(uint32_t value, uint32_t amount, uint32_t &carry_out) {
	if (amount == 0)
		return value;

	uint32_t amt = amount % 32;
	uint32_t result = Rotr32(value, amt);
	carry_out = get_bit(value, 31);
	return result;
}

// Implementation of: bits(N) ROR(bits(N) x, integer shift)
inline uint32_t ROR(uint32_t value, uint32_t amount) {
	if (amount == 0)
		return value;

	uint32_t unused;
	return ROR_C(value, amount, unused);
}

// Implementation of: (bits(N), bit) RRX_C(bits(N) x, bit carry_in)
inline uint32_t RRX_C(uint32_t value, uint32_t carry_in, uint32_t &carry_out) {
	carry_out = get_bit(value, 0);
	return get_bit(carry_in, 0) << 31 | get_bits(value, 31, 1);
}

// Implementation of: bits(N) RRX(bits(N) x, bit carry_in)
inline uint32_t RRX(uint32_t value, uint32_t carry_in) {
	uint32_t unused;
	return RRX_C(value, carry_in, unused);
}

// Implementation of: (bits(N), bit, bit) AddWithCarry(bits(N) x, bits(N) y, bit carry_in)
inline std::tuple<uint32_t, uint32_t, uint32_t> AddWithCarry(uint32_t x, uint32_t y, uint32_t carry_in) {
    uint64_t unsigned_sum = static_cast<uint64_t>(x) + static_cast<uint64_t>(y) + carry_in;
    int64_t signed_sum = static_cast<int64_t>(x) + static_cast<int64_t>(y) + carry_in;
    uint32_t result = static_cast<uint32_t>(unsigned_sum);
    uint32_t carry_out = (static_cast<uint32_t>(result) == unsigned_sum) ? 0 : 1;
    uint32_t overflow_out = (static_cast<int32_t>(result) == signed_sum) ? 0 : 1;
    return std::make_tuple(result, carry_out, overflow_out);
}

// Implementation of: (SRType, integer) DecodeImmShift(bits(2) type, bits(5) imm5)
inline std::tuple<uint32_t, uint32_t> DecodeImmShift(uint32_t type, uint32_t imm5) {
	switch (type) {
		case 0:
			return std::tuple<uint32_t, uint32_t>(SRType_LSL, imm5);
		case 1:
			return std::tuple<uint32_t, uint32_t>(SRType_LSR, imm5 == 0 ? 32 : imm5);
		case 2:
			return std::tuple<uint32_t, uint32_t>(SRType_ASR, imm5 == 0 ? 32 : imm5);
		case 3:
			if (imm5 == 0) {
				return std::tuple<uint32_t, uint32_t>(SRType_RRX, 1);
			} else {
				return std::tuple<uint32_t, uint32_t>(SRType_ROR, imm5);
			}
	}

	return std::tuple<uint32_t, uint32_t>(SRType_Invalid, UINT32_MAX);
}

// Implementation of: SRType DecodeRegShift(bits(2) type)
inline shift_t DecodeRegShift(uint32_t type) {
	switch (type) {
		default:
			return SRType_Invalid;
		case 0:
			return SRType_LSL;
		case 1:
			return SRType_LSR;
		case 2:
			return SRType_ASR;
		case 3:
			return SRType_ROR;
	}
}

// Implementation of: (bits(N), bit) Shift_C(bits(N) value, SRType type, integer amount, bit carry_in)
inline uint32_t Shift_C(uint32_t value, shift_t type, uint32_t amount, uint32_t carry_in, uint32_t &carry_out) {
	if (amount == 0) {
		carry_out = carry_in;
		return value;
	}

	uint32_t result;
	switch (type) {
		case SRType_LSL:
			result = LSL_C(value, amount, carry_out);
			break;
		case SRType_LSR:
			result = LSR_C(value, amount, carry_out);
			break;
		case SRType_ASR:
			result = ASR_C(value, amount, carry_out);
			break;
		case SRType_ROR:
			result = ROR_C(value, amount, carry_out);
			break;
		case SRType_RRX:
			result = RRX_C(value, carry_in, carry_out);
			break;
		default:
			abort();
	}

	return result;
}

inline uint32_t Shift_C(uint32_t value, uint32_t type, uint32_t amount, uint32_t carry_in, uint32_t &carry_out) {
	return Shift_C(value, static_cast<shift_t>(type), amount, carry_in, carry_out);
}

inline std::tuple<uint32_t, uint32_t> Shift_C(uint32_t value, shift_t type, uint32_t amount, uint32_t carry_in) {
	uint32_t result, carry_out;
	result = Shift_C(value, type, amount, carry_in, carry_out);
	return std::tuple<uint32_t, uint32_t>(result, carry_out);
}

inline std::tuple<uint32_t, uint32_t> Shift_C(uint32_t value, uint32_t type, uint32_t amount, uint32_t carry_in) {
	return Shift_C(value, static_cast<shift_t>(type), amount, carry_in);
}

// Implementation of: bits(N) Shift(bits(N) value, SRType type, integer amount, bit carry_in)
inline uint32_t Shift(uint32_t value, shift_t type, uint32_t amount, uint32_t carry_in) {
	uint32_t unused;
	return Shift_C(value, type, amount, carry_in, unused);
}

inline uint32_t Shift(uint32_t value, uint32_t type, uint32_t amount, uint32_t carry_in) {
	uint32_t unused;
	return Shift_C(value, static_cast<shift_t>(type), amount, carry_in, unused);
}

// Implementation of: (bits(32), bit) ARMExpandImm_C(bits(12) imm12, bit carry_in)
inline std::tuple<uint32_t, uint32_t> ARMExpandImm_C(uint32_t imm12, uint32_t carry_in) {
	uint32_t unrotated_value = get_bits(imm12, 7, 0);
	uint32_t carry_out;
	uint32_t imm32 = Shift_C(unrotated_value, SRType_ROR, 2 * get_bits(imm12, 11, 8), carry_in,
			carry_out);
	return std::tuple<uint32_t, uint32_t>(imm32, carry_out);
}

// Implementation of: bits(32) ARMExpandImm(bits(12) imm12)
inline uint32_t ARMExpandImm(uint32_t imm12) {
	// APSR.C argument to following function call does not affect the imm32 result.
	uint32_t carry_in = 0;
	return std::get<0>(ARMExpandImm_C(imm12, carry_in));
}

inline uint32_t ror(uint32_t val, uint32_t N, uint32_t shift) {
	uint32_t m = shift % N;
	return (val >> m) | (val << (N - m));
}

// (imm32, carry_out) = ThumbExpandImm_C(imm12, carry_in)
inline std::tuple<uint32_t, uint32_t> ThumbExpandImm_C(uint32_t imm12, uint32_t carry_in) {
	uint32_t imm12_7_0 = get_bits(imm12, 7, 0);
	uint32_t imm12_9_8 = get_bits(imm12, 9, 8);
	uint32_t imm12_11_10 = get_bits(imm12, 11, 10);
	unsigned carry_out;
	unsigned imm32;

	if (imm12_11_10 == 0) {
		switch (imm12_9_8) {
			default:
			case 0:
				imm32 = imm12_7_0;
				break;

			case 1:
				imm32 = imm12_7_0 << 16 | imm12_7_0;
				break;

			case 2:
				imm32 = imm12_7_0 << 24 | imm12_7_0 << 8;
				break;

			case 3:
				imm32 = imm12_7_0 << 24 | imm12_7_0 << 16 | imm12_7_0 << 8 | imm12_7_0;
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

inline uint32_t ThumbExpandImm(uint32_t opcode) {
	uint32_t carry_in = 0;
	return std::get<0>(ThumbExpandImm_C(opcode, carry_in));
}

inline uint64_t Replicate(uint64_t bit, int N) {
	if (!bit)
		return 0;

	if (N == 64) 
		return 0xffffffffffffffffLL;

	return (1ULL << N) - 1;
}

inline uint64_t Replicate32x2(uint64_t bits32) {
	return (bits32 << 32) | bits32;
}

inline uint64_t Replicate16x4(uint64_t bits16) {
	return Replicate32x2((bits16 << 16) | bits16);
}

inline uint64_t Replicate8x8(uint64_t bits8) {
	return Replicate16x4((bits8 << 8) | bits8);
}

inline uint64_t VFPExpandImm(uint64_t imm8, unsigned N) {
	unsigned E = ((N == 32) ? 8 : 11) - 2; // E in {6, 9}
	unsigned F = N - E - 1; // F in {25, 54}
	uint64_t imm8_6 = (imm8 >> 6) & 1; // imm8<6>
	uint64_t sign = (imm8 >> 7) & 1; // imm8<7>
	uint64_t exp = ((imm8_6 ^ 1) << (E - 1)) | Replicate(imm8_6, E - 1); // NOT(imm8<6>):Replicate(imm8<6>,{5, 8})
	uint64_t frac = ((imm8 & 0x3f) << (F - 6)) | Replicate(0, F - 6); // imm8<5:0> : Zeros({19, 48})
	uint64_t res = (sign << (E + F)) | (exp << F) | frac;
	return res;
}

// Implementation of: bits(64) AdvSIMDExpandImm(bit op, bits(4) cmode, bits(8) imm8)
inline uint64_t AdvSIMDExpandImm(unsigned op, unsigned cmode, unsigned imm8) {
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
			abort();
	}

	return imm64;
}

#endif /* ARMUTILITIES_H_ */
