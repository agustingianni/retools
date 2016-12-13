/*
 * ARMMath.h
 *
 *  Created on: Nov 4, 2015
 *      Author: anon
 */

#ifndef SRC_LIBEMULATION_ARMMATH_H_
#define SRC_LIBEMULATION_ARMMATH_H_

static inline bool CarryFrom8_add2(uint32_t a, uint32_t b) {
	return a + b > 0xff;
}

static inline bool CarryFrom16_add2(uint32_t a, uint32_t b) {
	return a + b > 0xffff;
}

static inline bool CarryFrom_add2(uint32_t a, uint32_t b) {
	return (a + b) < a;
}

static inline bool CarryFrom_add3(uint32_t a, uint32_t b, uint32_t c) {
	return CarryFrom_add2(a, b) || CarryFrom_add2(a + b, c);
}

static inline bool OverflowFrom_add2(uint32_t a, uint32_t b) {
	const uint32_t r = a + b;
	return ((a ^ ~b) & (a ^ r)) >> 31;
}

static inline bool OverflowFrom_add3(uint32_t a, uint32_t b, bool unused) {
	return OverflowFrom_add2(a, b);
}

static inline bool OverflowFrom_sub2(uint32_t a, uint32_t b) {
	const uint32_t r = a - b;
	return ((a ^ b) & (a ^ r)) >> 31;
}

static inline bool OverflowFrom_sub3(uint32_t a, uint32_t b, bool unused) {
	return OverflowFrom_sub2(a, b);
}

static inline uint32_t rotate_right(uint32_t x, uint32_t n) {
	if (n == 0)
		return x;

	return (x << (32 - n)) | (x >> n);
}

static inline uint32_t asr(uint32_t x, uint32_t n) {
	return ((int32_t) x) >> n;
}

static inline void set_field(uint32_t *dst, uint32_t a, uint32_t b, uint32_t src) {
	assert(a > b);
	const uint32_t mask = ((1 << (a - b)) - 1) << b;
	*dst &= ~mask;
	*dst |= src << b;
}

static inline uint32_t SignedSat32_add(int32_t a, int32_t b) {
	return SignedSat((int64_t) a + (int64_t) b, 32);
}

static inline uint32_t SignedSat32_sub(int32_t a, int32_t b) {
	return SignedSat((int64_t) a - (int64_t) b, 32);
}

static inline uint32_t SignedSat32_double(int32_t a) {
	return SignedSat(2 * (int64_t) a, 32);
}

static inline bool SignedDoesSat32_add(int32_t a, int32_t b) {
	return SignedDoesSat((int64_t) a + (int64_t) b, 32);
}

static inline bool SignedDoesSat32_sub(int32_t a, int32_t b) {
	return SignedDoesSat((int64_t) a - (int64_t) b, 32);
}

static inline bool SignedDoesSat32_double(int32_t a) {
	return SignedDoesSat(2 * (int64_t) a, 32);
}

static inline uint32_t SignedSat(int64_t x, uint32_t n) {
	if (x < -(1 << (n - 1)))
		return -(1 << (n - 1));
	if (x > (1 << (n - 1)) - 1)
		return (1 << (n - 1)) - 1;
	return x;
}

static inline uint32_t SignedDoesSat(int64_t x, uint32_t n) {
	return x < -(1 << (n - 1)) || x > (1 << (n - 1)) - 1;
}

static inline uint32_t UnsignedSat(int32_t x, uint32_t n) {
	assert(n < 32);
	if (x < 0)
		return 0;
	if (x > (1 << n) - 1)
		return (1 << n) - 1;
	return x;
}

static inline uint32_t UnsignedDoesSat(int32_t x, uint32_t n) {
	assert(n < 32);
	return x < 0 || x > (1 << n) - 1;
}

#endif /* SRC_LIBEMULATION_ARMMATH_H_ */
