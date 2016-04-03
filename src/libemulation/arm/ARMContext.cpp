/*
 * ARMContext.cpp
 *
 *  Created on: Oct 10, 2015
 *      Author: anon
 */
#include "ARMContext.h"

ARMContext::ARMContext() {
	// TODO Auto-generated constructor stub

}

ARMContext::~ARMContext() {
	// TODO Auto-generated destructor stub
}

uint32_t ARMContext::readRegularRegister(unsigned regno) {
	return 0;
}

uint32_t ARMContext::readRmode(unsigned regno, unsigned n) {
	return 0;
}

uint32_t ARMContext::readSingleRegister(unsigned regno) {
	return 0;
}

uint64_t ARMContext::readDoubleRegister(unsigned regno) {
	return 0;
}

uint64_t ARMContext::readQuadRegister(unsigned regno) {
	return 0;
}

uint32_t ARMContext::readMemory(uintptr_t address, unsigned size) {
	return 0;
}

uint32_t ARMContext::writeRegularRegister(unsigned regno, uintptr_t value) {
	return 0;
}

uint32_t ARMContext::writeRmode(unsigned regno, unsigned size, uintptr_t value) {
	return 0;
}

uint32_t ARMContext::writeSingleRegister(unsigned regno, float value) {
	return 0;
}

uint32_t ARMContext::writeDoubleRegister(unsigned regno, double value) {
	return 0;
}

uint32_t ARMContext::writeQuadRegister(unsigned regno, uint64_t value) {
	return 0;
}

uint32_t ARMContext::writeMemory(uintptr_t address, unsigned size, uintptr_t value) {
	return 0;
}

uint32_t ARMContext::readElement(uintptr_t address, uintptr_t value, unsigned size) {
	return 0;
}

uint32_t ARMContext::writeElement(uintptr_t address, unsigned size, uintptr_t value, unsigned what___) {
	return 0;
}

