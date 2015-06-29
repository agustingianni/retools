/*
 * Utilities.h
 *
 *  Created on: Oct 31, 2014
 *      Author: anon
 */

#ifndef UTILITIES_H_
#define UTILITIES_H_

#include <cassert>
#include <sstream>
#include <string>
#include <iostream>
#include <stdio.h>

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

static inline std::string exec_get_output(std::string cmd) {
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe)
		return "ERROR";

	char buffer[128];
	std::string result = "";

	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}

	pclose(pipe);
	return result;
}

static inline std::string integer_to_string(unsigned long long val, bool hexa = true) {
	std::stringstream ss;
	if (hexa) {
		ss << std::hex << "0x";
	} else {
		ss << std::dec;
	}

	ss << val;
	return ss.str();
}

static inline uint32_t NOT(uint32_t val, uint32_t bits) {
	return (~val) & ((1 << bits) - 1);
}

static inline uint32_t get_bits(uint32_t val, uint32_t msb, uint32_t lsb) {
	return (val >> lsb) & ((1 << (msb - lsb + 1)) - 1);
}

static inline uint32_t get_bit(uint32_t val, uint32_t lsb) {
	return (val >> lsb) & 1;
}

static inline uint32_t UInt(uint32_t val) {
	return val;
}

static inline uint32_t Align(uint32_t val, uint32_t alignment) {
	return alignment * (val / alignment);
}

template<unsigned B> static inline int32_t SignExtend(uint32_t x) {
	return int32_t(x << (32 - B)) >> (32 - B);
}

static inline int32_t SignExtend(uint32_t X, unsigned B) {
	return int32_t(X << (32 - B)) >> (32 - B);
}

template<unsigned B> static inline int32_t SignExtend32(uint32_t x) {
	return int32_t(x << (32 - B)) >> (32 - B);
}

static inline int32_t SignExtend32(uint32_t X, unsigned B) {
	return int32_t(X << (32 - B)) >> (32 - B);
}

template<unsigned B> static inline int64_t SignExtend64(uint64_t x) {
	return int64_t(x << (64 - B)) >> (64 - B);
}

static inline int64_t SignExtend64(uint64_t X, unsigned B) {
	return int64_t(X << (64 - B)) >> (64 - B);
}

static inline uint64_t MaskUpToBit(uint64_t bit) {
	return (1ull << (bit + 1ull)) - 1ull;
}

static unsigned Zeros(unsigned) {
	return 0;
}

static inline unsigned ZeroExtend(unsigned a, unsigned) {
	return a;
}

static inline uint32_t BitCount(uint64_t x) {
	uint32_t c;
	for (c = 0; x; ++c)
		x &= x - 1;

	return c;
}

static inline bool BitIsSet(uint64_t value, uint64_t bit) {
	return (value & (1ull << bit)) != 0;
}

static inline bool BitIsClear(uint64_t value, uint64_t bit) {
	return (value & (1ull << bit)) == 0;
}

static inline uint64_t UnsignedBits(uint64_t value, uint64_t msbit, uint64_t lsbit) {
	uint64_t result = value >> lsbit;
	result &= MaskUpToBit(msbit - lsbit);
	return result;
}

static inline int64_t SignedBits(uint64_t value, uint64_t msbit, uint64_t lsbit) {
	uint64_t result = UnsignedBits(value, msbit, lsbit);
	if (BitIsSet(value, msbit)) {
		result |= ~MaskUpToBit(msbit - lsbit);
	}

	return result;
}

static inline uint32_t Rotr32(uint32_t bits, uint32_t amt) {
	assert(amt < 32 && "Invalid rotate amount");
	return (bits >> amt) | (bits << ((32 - amt) & 31));
}

static inline uint32_t Rotl32(uint32_t bits, uint32_t amt) {
	assert(amt < 32 && "Invalid rotate amount");
	return (bits << amt) | (bits >> ((32 - amt) & 31));
}

static inline uint32_t Concatenate(uint32_t val_1, uint32_t val_2, uint32_t val_2_size) {
	return (val_1 << val_2_size) | val_2;
}

#endif /* UTILITIES_H_ */
