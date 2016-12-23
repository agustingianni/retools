#include <arm/ARMDisassembler.h>
#include <arm/gen/ARMDecodingTable.h>
#include <iostream>
#include <limits>
#include <cassert>
#include <cstdio>

#include <unicorn/unicorn.h>

#include "Utilities.h"
#include "test_utils.h"

using namespace Disassembler;

std::string retools_disassemble(uint32_t opcode, unsigned mode) {
	ARMDisassembler dis(ARMvAll);
	ARMInstruction ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	return ins.toString();
}

struct instruction_effects {
    uint32_t regular_regs[16];
};

struct instruction_effects uc_instruction_effects(uc_engine *uc) {
    struct instruction_effects effects;

    uc_reg_read(uc, UC_ARM_REG_R0, &effects.regular_regs[0]);
	uc_reg_read(uc, UC_ARM_REG_R1, &effects.regular_regs[1]);
	uc_reg_read(uc, UC_ARM_REG_R2, &effects.regular_regs[2]);
	uc_reg_read(uc, UC_ARM_REG_R3, &effects.regular_regs[3]);
	uc_reg_read(uc, UC_ARM_REG_R4, &effects.regular_regs[4]);
	uc_reg_read(uc, UC_ARM_REG_R5, &effects.regular_regs[5]);
	uc_reg_read(uc, UC_ARM_REG_R6, &effects.regular_regs[6]);
	uc_reg_read(uc, UC_ARM_REG_R7, &effects.regular_regs[7]);
	uc_reg_read(uc, UC_ARM_REG_R8, &effects.regular_regs[8]);
	uc_reg_read(uc, UC_ARM_REG_R9, &effects.regular_regs[9]);
	uc_reg_read(uc, UC_ARM_REG_R10, &effects.regular_regs[10]);
	uc_reg_read(uc, UC_ARM_REG_R11, &effects.regular_regs[11]);
	uc_reg_read(uc, UC_ARM_REG_R12, &effects.regular_regs[12]);
	uc_reg_read(uc, UC_ARM_REG_R13, &effects.regular_regs[13]);
	uc_reg_read(uc, UC_ARM_REG_R14, &effects.regular_regs[14]);
	uc_reg_read(uc, UC_ARM_REG_R15, &effects.regular_regs[15]);

    return effects;
}

void uc_set_initial_state(uc_engine *uc) {
    uint32_t value = 2;
    uc_reg_write(uc, UC_ARM_REG_R0, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R1, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R2, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R3, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R4, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R5, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R6, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R7, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R8, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R9, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R10, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R11, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R12, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R13, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R14, &value); value += value;
	uc_reg_write(uc, UC_ARM_REG_R15, &value); value += value;
}

void uc_print_state(uc_engine *uc) {
	uint32_t rr[16];
    uc_reg_read(uc, UC_ARM_REG_R0, &rr[0]);
	uc_reg_read(uc, UC_ARM_REG_R1, &rr[1]);
	uc_reg_read(uc, UC_ARM_REG_R2, &rr[2]);
	uc_reg_read(uc, UC_ARM_REG_R3, &rr[3]);
	uc_reg_read(uc, UC_ARM_REG_R4, &rr[4]);
	uc_reg_read(uc, UC_ARM_REG_R5, &rr[5]);
	uc_reg_read(uc, UC_ARM_REG_R6, &rr[6]);
	uc_reg_read(uc, UC_ARM_REG_R7, &rr[7]);
	uc_reg_read(uc, UC_ARM_REG_R8, &rr[8]);
	uc_reg_read(uc, UC_ARM_REG_R9, &rr[9]);
	uc_reg_read(uc, UC_ARM_REG_R10, &rr[10]);
	uc_reg_read(uc, UC_ARM_REG_R11, &rr[11]);
	uc_reg_read(uc, UC_ARM_REG_R12, &rr[12]);
	uc_reg_read(uc, UC_ARM_REG_R13, &rr[13]);
	uc_reg_read(uc, UC_ARM_REG_R14, &rr[14]);
	uc_reg_read(uc, UC_ARM_REG_R15, &rr[15]);

	printf("Regular registers:\n");
	printf("r0  = 0x%.8x r1  = 0x%.8x r2  = 0x%.8x r3  = 0x%.8x r4  = 0x%.8x r5  = 0x%.8x r6  = 0x%.8x r7  = 0x%.8x\n",
		rr[0], rr[1], rr[2], rr[3], rr[4], rr[5], rr[6], rr[7]
	);

	printf("r8  = 0x%.8x r9  = 0x%.8x r10 = 0x%.8x r11 = 0x%.8x r12 = 0x%.8x r13 = 0x%.8x r14 = 0x%.8x r15 = 0x%.8x\n",
		rr[8], rr[9], rr[10], rr[11], rr[12], rr[13], rr[14], rr[15]
	);
}

struct instruction_effects unicorn_run(uint32_t opcode, unsigned mode) {
    constexpr uintptr_t ADDRESS = 0xcafe0000;

    uc_engine *uc;
    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);

    // Map the memory we will use.
    uc_mem_map(uc, ADDRESS, 4096, UC_PROT_ALL);

    // Write the instruction.
    uc_mem_write(uc, ADDRESS, &opcode, sizeof(opcode) - 1);

    // Prepare the state.
    uc_set_initial_state(uc);

    // Emulate only one instruction.
    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(opcode) - 1, 0, 1);

	// Print the internal state.
	uc_print_state(uc);

	// Get instruction effects.
	auto effects = uc_instruction_effects(uc);

    // uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_close(uc);

	return {};
}

struct instruction_effects retools_run(uint32_t opcode, unsigned mode) {
	return {};
}

struct instruction_effects hardware_run(uint32_t opcode, unsigned mode) {
	return {};
}

void test_arm(unsigned n, unsigned start, unsigned finish, FILE *file) {
	uint32_t mask;
	uint32_t value;
	uint32_t op_code;

	if (start == finish || finish > n_arm_opcodes) {
		finish = n_arm_opcodes - 1;
	}

	for (unsigned i = start; i < finish; ++i) {
		mask = arm_opcodes[i].mask;
		value = arm_opcodes[i].value;

		printf("Emulating instruction '%s'\n", arm_opcodes[i].name);

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random(mask, value);

			// We avoid generating condition codes of 0b1111.
			if (get_bit(mask, 28) == 0) {
				op_code &= 0xefffffff;
			}

			printf("  %s\n", retools_disassemble(op_code, 0).c_str());
            // Run the instruction.
            auto r0 = unicorn_run(op_code, 0);
            auto r1 = retools_run(op_code, 0);
		}
	}
}

void test_thumb(unsigned n, unsigned start, unsigned finish, FILE *file) {
	uint32_t mask;
	uint32_t value;
	uint32_t size;
	uint32_t op_code;

	if (start == finish || finish > n_thumb_opcodes) {
		finish = n_thumb_opcodes - 1;
	}

	for (unsigned i = start; i < finish; ++i) {
		mask = thumb_opcodes[i].mask;
		value = thumb_opcodes[i].value;
		size = thumb_opcodes[i].ins_size == eSize16 ? 16 : 32;

        printf("Emulating instruction '%s'\n", thumb_opcodes[i].name);

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random(mask, value, size);
			unsigned caps_op_code = size == 32 ? ((op_code & 0xffff) << 16 ) | (op_code >> 16) : op_code;

            // Run the instruction.
            auto r0 = unicorn_run(caps_op_code, 1);
            auto r1 = retools_run(op_code, 1);
		}
	}
}

void test(unsigned n, unsigned start, unsigned finish, unsigned mode, char *path) {
	if (mode == 0) {
		test_arm(n, start, finish, nullptr);
	} else {
		test_thumb(n, start, finish, nullptr);
	}
}

int main(int argc, char **argv) {
	if (argc <= 5) {
		printf("Usage: %s <iterations> <start> <finish> <mode> <outfile>\n", argv[0]);
		printf("  <iterations>: Number of times we will randomly generate the same instruction.\n");
		printf("  <start>:      Index to the first instruction to be tested.\n");
		printf("                  From 0 to %u for THUMB instructions.\n", n_thumb_opcodes - 1);
		printf("                  From 0 to %u for ARM instructions.\n", n_arm_opcodes - 1);
		printf("  <finish>:     Index to the last instruction to be tested.\n");
		printf("                  If <start> == <finish> then all instructions are tested.\n");
		printf("  <mode>:       0 for ARM , 1 for THUMB.\n");
		printf("  <outfile>:    File name to save results.\n");
		return -1;
	}

	unsigned n = std::stoi(argv[1]);
	unsigned i = std::stoi(argv[2]);
	unsigned j = std::stoi(argv[3]);
	unsigned k = std::stoi(argv[4]);
	char *path = argv[5];

	printf("Testing random instructions from %u to %u, %u times in mode %s.\n", i, j, n, !k ? "ARM" : "THUMB");
	printf("Saving results to '%s'\n", path);

	test(n, i, j, k, path);
	return 0;
}
