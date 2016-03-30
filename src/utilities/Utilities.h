/*
 * Utilities.h
 *
 *  Created on: Oct 31, 2014
 *      Author: anon
 */

#ifndef UTILITIES_H_
#define UTILITIES_H_

#include <string>
#include <sstream>
#include <cassert>
#include <cstdint>
#include <cstdio>

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

inline bool IsZeroBit(unsigned i) {
	return i == 0;
}

inline bool IsHostBigEndian(void) {
	union {
		uint32_t i;
		char c[sizeof(uint32_t)];
	} bint = { 0x01020304 };

	return bint.c[0] == 1;
}

inline std::string exec_get_output(std::string cmd) {
    auto pipe_file = popen(cmd.c_str(), "r");
    if (!pipe_file)
        return "ERROR";

    char buffer[128];
    std::string result = "";

    while (!feof(pipe_file)) {
        if (fgets(buffer, 128, pipe_file) != NULL)
            result += buffer;
    }

    pclose(pipe_file);
    return result;
}

inline std::string integer_to_string(unsigned long long val, bool hexa = true) {
	std::stringstream ss;
	if (hexa) {
		ss << std::hex << "0x";
	} else {
		ss << std::dec;
	}

	ss << val;
	return ss.str();
}

inline uint32_t NOT(uint32_t val, uint32_t bits) {
	return (~val) & ((1 << bits) - 1);
}

inline uint32_t get_bits(uint32_t val, uint32_t msb, uint32_t lsb) {
	return (val >> lsb) & ((1 << (msb - lsb + 1)) - 1);
}

inline uint32_t get_bit(uint32_t val, uint32_t lsb) {
	return (val >> lsb) & 1;
}

inline void set_bits(uint32_t &out, uint32_t msb, uint32_t lsb, uint64_t val) {
	uint32_t lo_val = ((1 << lsb) - 1) & out;
	uint32_t hi_val = (out >> (msb + 1)) << (msb + 1);
	out = hi_val | (val << lsb) | lo_val;
}

inline void set_bits(int &out, uint32_t msb, uint32_t lsb, uint64_t val) {
	uint32_t lo_val = ((1 << lsb) - 1) & out;
	uint32_t hi_val = (out >> (msb + 1)) << (msb + 1);
	out = (int) (hi_val | (val << lsb) | lo_val);
}

inline void set_bit(uint32_t &number, uint32_t n, uint32_t x) {
	number ^= (-x ^ number) & (1 << n);
}

inline void set_bit(int &number, uint32_t n, uint32_t x) {
	number ^= (-x ^ number) & (1 << n);
}

inline uint32_t UInt(uint32_t val) {
	return val;
}

inline uint32_t Align(uint32_t val, uint32_t alignment) {
	return alignment * (val / alignment);
}

template<unsigned B> inline int32_t SignExtend(uint32_t x) {
	return int32_t(x << (32 - B)) >> (32 - B);
}

inline int32_t SignExtend(uint32_t X, unsigned B) {
	return int32_t(X << (32 - B)) >> (32 - B);
}

template<unsigned B> inline int32_t SignExtend32(uint32_t x) {
	return int32_t(x << (32 - B)) >> (32 - B);
}

inline int32_t SignExtend32(uint32_t X, unsigned B) {
	return int32_t(X << (32 - B)) >> (32 - B);
}

template<unsigned B> inline int64_t SignExtend64(uint64_t x) {
	return int64_t(x << (64 - B)) >> (64 - B);
}

inline int64_t SignExtend64(uint64_t X, unsigned B) {
	return int64_t(X << (64 - B)) >> (64 - B);
}

inline uint64_t MaskUpToBit(uint64_t bit) {
	return (1ull << (bit + 1ull)) - 1ull;
}

inline unsigned Zeros(unsigned) {
	return 0;
}

inline unsigned ZeroExtend(unsigned a, unsigned) {
	return a;
}

inline bool IsZero(unsigned a) {
	return !a;
}

inline uint32_t BitCount(uint64_t x) {
	uint32_t c;
	for (c = 0; x; ++c)
		x &= x - 1;

	return c;
}

inline bool BitIsSet(uint64_t value, uint64_t bit) {
	return (value & (1ull << bit)) != 0;
}

inline bool BitIsClear(uint64_t value, uint64_t bit) {
	return (value & (1ull << bit)) == 0;
}

inline uint64_t UnsignedBits(uint64_t value, uint64_t msbit, uint64_t lsbit) {
	uint64_t result = value >> lsbit;
	result &= MaskUpToBit(msbit - lsbit);
	return result;
}

inline int64_t SignedBits(uint64_t value, uint64_t msbit, uint64_t lsbit) {
	uint64_t result = UnsignedBits(value, msbit, lsbit);
	if (BitIsSet(value, msbit)) {
		result |= ~MaskUpToBit(msbit - lsbit);
	}

	return result;
}

inline uint32_t Rotr32(uint32_t bits, uint32_t amt) {
	assert(amt < 32 && "Invalid rotate amount");
	return (bits >> amt) | (bits << ((32 - amt) & 31));
}

inline uint32_t Rotl32(uint32_t bits, uint32_t amt) {
	assert(amt < 32 && "Invalid rotate amount");
	return (bits << amt) | (bits >> ((32 - amt) & 31));
}

inline uint32_t Concatenate(uint32_t val_1, uint32_t val_2, uint32_t val_2_size) {
	return (val_1 << val_2_size) | val_2;
}

#endif /* UTILITIES_H_ */
