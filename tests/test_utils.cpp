#include <random>
#include <cassert>

#include "test_utils.h"

using namespace std;

template<class T> T get_random_int() {
	static random_device rd;
	uniform_int_distribution<T> uniform_dist(numeric_limits<T>::min(), numeric_limits<T>::max());
	return uniform_dist(rd);
}

uint32_t get_masked_random(uint32_t mask, uint32_t value, uint32_t size) {
	uint32_t r = get_random_int<uint32_t>() & ((size != 32) ? 0xffff : 0xffffffff);

	for (uint32_t i = 0; i < size; ++i) {
		if (mask & (1 << i)) {
			if (value & (1 << i)) {
				r |= value & (1 << i);
			} else {
				r &= ~(1 << i);
			}
		}
	}

	assert((r & mask) == value);
	return r;
}
