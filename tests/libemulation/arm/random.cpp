#include <arm/ARMDisassembler.h>
#include <arm/gen/ARMDecodingTable.h>
#include <iostream>
#include <limits>
#include <cassert>
#include <cstdio>
#include <array>
#include <algorithm>
#include <memory>

#include <unicorn/unicorn.h>

#include <arm/ARMArch.h>
#include <arm/ARMEmulator.h>
#include <memory/Memory.h>

#include "Utilities.h"
#include "test_utils.h"
#include "debug.h"

using namespace Memory;
using namespace Register;
using namespace Emulator;
using namespace Disassembler;

std::string retools_disassemble(uint32_t opcode, unsigned mode) {
	ARMDisassembler dis(ARMvAll);
	ARMInstruction ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	return ins.toString();
}

using f64_t = double;
using u32_t = uint32_t;
using u64_t = uint64_t;

template <typename T>
void uc_reg_read_batch(uc_engine *uc, int regid, int count, T *buffer) {
	for (auto i = 0; i < count; i++) {
		uc_reg_read(uc, regid + i, &buffer[i]);
	}
}

template <typename T>
void uc_reg_write_batch(uc_engine *uc, int regid, int count, T *buffer) {
	for (auto i = 0; i < count; i++) {
		uc_reg_write(uc, regid + i, &buffer[i]);
	}
}

struct instruction_effects {
    std::array<u32_t, 16> regular_regs;
	std::array<u64_t, 32> double_regs;

	static void print(const instruction_effects &effects) {
		LOG_BLUE("| Regular 32 bit registers:");
		LOG_MAGENTA(
			"|  r0:0x%.8x  r1:0x%.8x  r2:0x%.8x  r3:0x%.8x",
			effects.regular_regs[0], effects.regular_regs[1],
			effects.regular_regs[2], effects.regular_regs[3]
		);

		LOG_MAGENTA(
			"|  r4:0x%.8x  r5:0x%.8x  r6:0x%.8x  r7:0x%.8x",
			effects.regular_regs[4], effects.regular_regs[5],
			effects.regular_regs[6], effects.regular_regs[7]
		);

		LOG_MAGENTA(
			"|  r8:0x%.8x  r9:0x%.8x r10:0x%.8x r11:0x%.8x",
			effects.regular_regs[8], effects.regular_regs[9],
			effects.regular_regs[10], effects.regular_regs[11]
		);

		LOG_MAGENTA(
			"| r12:0x%.8x r13:0x%.8x r14:0x%.8x r15:0x%.8x",
			effects.regular_regs[12], effects.regular_regs[13],
			effects.regular_regs[14], effects.regular_regs[15]
		);

		LOG_BLUE("| Floating point 64 bit registers:");
		LOG_MAGENTA(
			"|  d0:0x%.16llx  d1:0x%.16llx  d2:0x%.16llx  d3:0x%.16llx",
			effects.double_regs[0], effects.double_regs[1],
			effects.double_regs[2], effects.double_regs[3]
		);

		LOG_MAGENTA(
			"|  d4:0x%.16llx  d5:0x%.16llx  d6:0x%.16llx  d7:0x%.16llx",
			effects.double_regs[4], effects.double_regs[5],
			effects.double_regs[6], effects.double_regs[7]
		);

		LOG_MAGENTA(
			"|  d8:0x%.16llx  d9:0x%.16llx d10:0x%.16llx d11:0x%.16llx",
			effects.double_regs[8], effects.double_regs[9],
			effects.double_regs[10], effects.double_regs[11]
		);

		LOG_MAGENTA(
			"| d12:0x%.16llx d13:0x%.16llx d14:0x%.16llx d15:0x%.16llx",
			effects.double_regs[12], effects.double_regs[13],
			effects.double_regs[14], effects.double_regs[15]
		);

		LOG_MAGENTA(
			"| d16:0x%.16llx d17:0x%.16llx d18:0x%.16llx d19:0x%.16llx",
			effects.double_regs[16], effects.double_regs[17],
			effects.double_regs[18], effects.double_regs[19]
		);

		LOG_MAGENTA(
			"| d20:0x%.16llx d21:0x%.16llx d22:0x%.16llx d23:0x%.16llx",
			effects.double_regs[20], effects.double_regs[21],
			effects.double_regs[22], effects.double_regs[23]
		);

		LOG_MAGENTA(
			"| d24:0x%.16llx d25:0x%.16llx d26:0x%.16llx d27:0x%.16llx",
			effects.double_regs[24], effects.double_regs[25],
			effects.double_regs[26], effects.double_regs[27]
		);

		LOG_MAGENTA(
			"| d28:0x%.16llx d29:0x%.16llx d30:0x%.16llx d31:0x%.16llx",
			effects.double_regs[28], effects.double_regs[29],
			effects.double_regs[30], effects.double_regs[31]
		);
	}
};

enum class CPUMode {
	ARM_MODE,
	THUMB_MODE
};

class InstructionInspector {
public:
	virtual void run(CPUMode mode, uint32_t opcode) = 0;
	virtual void reset() = 0;
	virtual instruction_effects effects() = 0;

protected:
	constexpr static uintptr_t m_base = 0xcafe0000;
	constexpr static size_t m_base_size = 4096;
};

class UnicornInstructionInspector: public InstructionInspector {
public:
	UnicornInstructionInspector() {
		// Create an ARM cpu.
		uc_open(UC_ARCH_ARM, UC_MODE_ARM, &m_engine);

		// Create a scratch area for code.
		uc_mem_map(m_engine, m_base, m_base_size, UC_PROT_ALL);
		uc_mem_write(m_engine, m_base, &zero[0], zero.size());

		// Generate special values for registers.
		u32_t integer_init_val = 2;
		std::array<u32_t, 16> u32_values;
		std::generate_n(u32_values.begin(), u32_values.size(), [&integer_init_val] {
			integer_init_val = integer_init_val * 2;
			return integer_init_val;
		});

		u64_t double_init_val = 2;
		std::array<u64_t, 32> f64_values;
		std::generate_n(f64_values.begin(), f64_values.size(), [&double_init_val] {
			double_init_val = double_init_val * 2;
			return double_init_val;
		});

		// Write the test values.
		uc_reg_write_batch<u32_t>(m_engine, UC_ARM_REG_R0, u32_values.size(), u32_values.data());
		uc_reg_write_batch<u64_t>(m_engine, UC_ARM_REG_D0, f64_values.size(), f64_values.data());

		// Create a backup context for later fast restoration.
		uc_context_alloc(m_engine, &m_context);
		uc_context_save(m_engine, m_context);
	}

	~UnicornInstructionInspector() {
		uc_context_free(m_context);
		uc_close(m_engine);
	}

	void run(CPUMode mode, uint32_t opcode) override {
		// Write the instruction and emulate it.
		uc_mem_write(m_engine, m_base, &opcode, sizeof(opcode) - 1);
		uc_emu_start(m_engine, m_base, m_base + sizeof(opcode) - 1, 0, 1);
	}

	instruction_effects effects() override {
		instruction_effects effects;

		uc_reg_read_batch<u32_t>(m_engine, UC_ARM_REG_R0, effects.regular_regs.size(), effects.regular_regs.data());
		uc_reg_read_batch<u64_t>(m_engine, UC_ARM_REG_D0, effects.double_regs.size(), effects.double_regs.data());

		return effects;
	}

	void reset() override {
		uc_context_restore(m_engine, m_context);
		uc_mem_write(m_engine, m_base, &zero[0], zero.size());
	}

private:
	uc_engine *m_engine;
	uc_context *m_context;

	std::array<uint8_t, m_base_size> zero{};
};

class REToolsInstructionInspector: public InstructionInspector {
	std::unique_ptr<ARMEmulator> m_emulator;
	std::unique_ptr<ConcreteMemory> m_memory;
	std::unique_ptr<ARMContext> m_context;
	ARMContext m_saved_context;

public:
	REToolsInstructionInspector() {
		m_memory = std::make_unique<ConcreteMemory>();
		m_context = std::make_unique<ARMContext>(m_memory.get());
		m_emulator = std::make_unique<ARMEmulator>(m_context.get(), m_memory.get(), ARMMode::ARMMode_ARM);

		m_memory->map(m_base, m_base_size, 0);

		// Generate special values for registers.
		u32_t integer_init_val = 2;
		std::array<u32_t, 16> u32_values;
		std::generate_n(u32_values.begin(), u32_values.size(), [&integer_init_val] {
			integer_init_val = integer_init_val * 2;
			return integer_init_val;
		});

		u64_t double_init_val = 2;
		std::array<u64_t, 32> f64_values;
		std::generate_n(f64_values.begin(), f64_values.size(), [&double_init_val] {
			double_init_val = double_init_val * 2;
			return double_init_val;
		});

		m_context->setCoreRegisters(u32_values);
		m_context->setDoubleRegisters(f64_values);
		m_context->setRegister(ARM_REG_PC, 0xcafe0000);

		m_saved_context = *m_context;
	}

	~REToolsInstructionInspector() {
	}

	void run(CPUMode mode, uint32_t opcode) override {
		m_memory->write_value(m_base, opcode);
		m_emulator->start(1);
	}

	instruction_effects effects() override {
		instruction_effects effects;
		effects.regular_regs = m_context->getCoreRegisters();
		effects.double_regs = m_context->getDoubleRegisters();
		return effects;
	}

	void reset() override {
		*m_context = m_saved_context;
	}
};

class HardwareInstructionInspector: public InstructionInspector {
public:
	HardwareInstructionInspector() {
	}

	~HardwareInstructionInspector() {
	}

	void run(CPUMode mode, uint32_t opcode) override {
	}

	instruction_effects effects() override {
		return {};
	}

	void reset() override {
	}
};

void test_arm(unsigned n, unsigned start, unsigned finish, FILE *file) {
	uint32_t mask;
	uint32_t value;
	uint32_t op_code;

	if (start == finish || finish > n_arm_opcodes) {
		finish = n_arm_opcodes - 1;
	}

	UnicornInstructionInspector unicorn_inspector;
	REToolsInstructionInspector retools_inspector;
	HardwareInstructionInspector hardware_inspector;

	for (unsigned i = start; i < finish; ++i) {
		mask = arm_opcodes[i].mask;
		value = arm_opcodes[i].value;

		LOG_YELLOW("Emulating instruction '%s'", arm_opcodes[i].name);

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random(mask, value);

			// We avoid generating condition codes of 0b1111.
			if (get_bit(mask, 28) == 0) {
				op_code &= 0xefffffff;
			}

			LOG_GREEN("+------------------------------------------------------------------------------+");
			LOG_GREEN("| %s", retools_disassemble(op_code, 0).c_str());
			LOG_GREEN("+------------------------------------------------------------------------------+");

			// Run the instruction.
            unicorn_inspector.run(CPUMode::ARM_MODE, op_code);
            retools_inspector.run(CPUMode::ARM_MODE, op_code);
			hardware_inspector.run(CPUMode::ARM_MODE, op_code);

			// Collect the effects.
			auto r0 = unicorn_inspector.effects();
			auto r1 = retools_inspector.effects();
			auto r2 = hardware_inspector.effects();

			// Reset to initial state.
			unicorn_inspector.reset();
			retools_inspector.reset();
			hardware_inspector.reset();

			// Debug.
			LOG_WHITE("+------------------------------------------------------------------------------+");
			instruction_effects::print(r0);
			LOG_WHITE("+------------------------------------------------------------------------------+");
			instruction_effects::print(r1);
			LOG_WHITE("+------------------------------------------------------------------------------+");

			// instruction_effects::print(r2);
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

        LOG_INFO("Emulating instruction '%s'", thumb_opcodes[i].name);

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random(mask, value, size);
			unsigned caps_op_code = size == 32 ? ((op_code & 0xffff) << 16 ) | (op_code >> 16) : op_code;
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
		LOG_INFO("Usage: %s <iterations> <start> <finish> <mode> <outfile>", argv[0]);
		LOG_INFO("  <iterations>: Number of times we will randomly generate the same instruction.");
		LOG_INFO("  <start>:      Index to the first instruction to be tested.");
		LOG_INFO("                  From 0 to %u for THUMB instructions.", n_thumb_opcodes - 1);
		LOG_INFO("                  From 0 to %u for ARM instructions.", n_arm_opcodes - 1);
		LOG_INFO("  <finish>:     Index to the last instruction to be tested.");
		LOG_INFO("                  If <start> == <finish> then all instructions are tested.");
		LOG_INFO("  <mode>:       0 for ARM , 1 for THUMB.");
		LOG_INFO("  <outfile>:    File name to save results.");
		return -1;
	}

	unsigned n = std::stoi(argv[1]);
	unsigned i = std::stoi(argv[2]);
	unsigned j = std::stoi(argv[3]);
	unsigned k = std::stoi(argv[4]);
	char *path = argv[5];

	LOG_INFO("Testing random instructions from %u to %u, %u times in mode %s.", i, j, n, !k ? "ARM" : "THUMB");
	LOG_INFO("Saving results to '%s'", path);

	test(n, i, j, k, path);
	return 0;
}
