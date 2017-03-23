#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <tuple>
#include <vector>
#include <stdio.h>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#include <arm/ARMArch.h>
#include <arm/ARMDisassembler.h>
#include <arm/ARMEmulator.h>
#include <arm/gen/ARMDecodingTable.h>
#include <memory/Memory.h>

#include "Utilities.h"
#include "test_utils.h"
#include "debug.h"

using namespace Memory;
using namespace Register;
using namespace Emulator;
using namespace Disassembler;

using u32_t = uint32_t;
using u64_t = uint64_t;

constexpr const u32_t INITIAL_CPSR_VALUE = 0x40000010;

std::string cpsr_to_string(u32_t value) {
	cpsr_t cpsr = *reinterpret_cast<cpsr_t *>(&value);
	char buffer[512];
	snprintf(buffer, sizeof(buffer), "0x%.8x -> N=%u Z=%u C=%u V=%u Q=%u IT_1_0=%2u J=%u RAZ=%4u GE=%4u IT_7_2=%4u E=%u A=%u I=%u F=%u T=%u M=%4u",
		value, cpsr.N, cpsr.Z, cpsr.C, cpsr.V, cpsr.Q, cpsr.IT_1_0, cpsr.J, cpsr.RAZ, cpsr.GE, cpsr.IT_7_2, cpsr.E, cpsr.A, cpsr.I, cpsr.F, cpsr.T, cpsr.M);

	return std::string(buffer);
}

std::string retools_disassemble(uint32_t opcode, unsigned mode) {
	ARMDisassembler dis(ARMvAll);
	ARMInstruction ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	return ins.toString();
}

std::string capstone_disassemble(uint32_t op_code, unsigned mode) {
	csh handle;
	cs_insn *insn;
	size_t count;
	std::string ret = "INVALID";

	cs_mode cmode = mode == 0 ? CS_MODE_ARM : CS_MODE_THUMB;
	cs_open(CS_ARCH_ARM, cmode, &handle);
	{
		count = cs_disasm(handle, (unsigned char *) &op_code, sizeof(op_code), 0, 0, &insn);
		if (count) {
			ret = std::string(insn[0].mnemonic) + " " + std::string(insn[0].op_str);
			cs_free(insn, count);
		}
	}
	cs_close(&handle);

	return ret;
}

static std::array<int, 16> all_rr = {
	UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
	UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
	UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
	UC_ARM_REG_R12, UC_ARM_REG_R13, UC_ARM_REG_R14, UC_ARM_REG_R15
};

static std::array<int, 32> all_dr = {
	UC_ARM_REG_D0, UC_ARM_REG_D1, UC_ARM_REG_D2, UC_ARM_REG_D3,
	UC_ARM_REG_D4, UC_ARM_REG_D5, UC_ARM_REG_D6, UC_ARM_REG_D7,
	UC_ARM_REG_D8, UC_ARM_REG_D9, UC_ARM_REG_D10, UC_ARM_REG_D11,
	UC_ARM_REG_D12, UC_ARM_REG_D13, UC_ARM_REG_D14, UC_ARM_REG_D15,
	UC_ARM_REG_D16, UC_ARM_REG_D17, UC_ARM_REG_D18, UC_ARM_REG_D19,
	UC_ARM_REG_D20, UC_ARM_REG_D21, UC_ARM_REG_D22, UC_ARM_REG_D23,
	UC_ARM_REG_D24, UC_ARM_REG_D25, UC_ARM_REG_D26, UC_ARM_REG_D27,
	UC_ARM_REG_D28, UC_ARM_REG_D29, UC_ARM_REG_D30, UC_ARM_REG_D31
};

void uc_reg_read_batch(uc_engine *uc, u32_t *buffer) {
	std::array<u32_t *, 16> ptrs;
	for (auto i = 0; i < 16; i++)
		ptrs[i] = &buffer[i];

	uc_reg_read_batch(uc, all_rr.data(), (void **) ptrs.data(), all_rr.size());
}

void uc_reg_read_batch(uc_engine *uc, u64_t *buffer) {
	std::array<u64_t *, 32> ptrs;
	for (auto i = 0; i < 32; i++)
		ptrs[i] = &buffer[i];

	uc_reg_read_batch(uc, all_dr.data(), (void **) ptrs.data(), all_dr.size());
}

void uc_reg_write_batch(uc_engine *uc, u32_t *buffer) {
	std::array<u32_t *, 16> ptrs;
	for (auto i = 0; i < 16; i++)
		ptrs[i] = &buffer[i];

	uc_reg_write_batch(uc, all_rr.data(), (void **) ptrs.data(), all_rr.size());
}

void uc_reg_write_batch(uc_engine *uc, u64_t *buffer) {
	std::array<u64_t *, 32> ptrs;
	for (auto i = 0; i < 32; i++)
		ptrs[i] = &buffer[i];

	uc_reg_write_batch(uc, all_dr.data(), (void **) ptrs.data(), all_dr.size());
}

struct instruction_effects {
	static constexpr unsigned N_REGULAR_REGS = 16;
	static constexpr unsigned N_DOUBLE_REGS = 32;

    std::array<u32_t, N_REGULAR_REGS> regular_regs;
	std::array<u64_t, N_DOUBLE_REGS> double_regs;
	u32_t cpsr;

	bool operator==(const instruction_effects &other) const {
		return this->regular_regs == other.regular_regs && this->double_regs == other.double_regs && this->cpsr == other.cpsr;
	}

	bool operator!=(const instruction_effects &other) const {
		return !(*this == other);
	}

	static void print(const instruction_effects &effects) {
		print_cpsr(effects);
		print_regular_registers(effects);
		print_double_registers(effects);
	}

	static void print_cpsr(const instruction_effects &effects) {
		LOG_BLUE("CPSR: %s", cpsr_to_string(effects.cpsr).c_str());
	}

	static void print_regular_registers(const instruction_effects &effects) {
		LOG_BLUE(
			" r0:0x%.8x  r1:0x%.8x  r2:0x%.8x  r3:0x%.8x",
			effects.regular_regs[0], effects.regular_regs[1],
			effects.regular_regs[2], effects.regular_regs[3]
		);

		LOG_BLUE(
			" r4:0x%.8x  r5:0x%.8x  r6:0x%.8x  r7:0x%.8x",
			effects.regular_regs[4], effects.regular_regs[5],
			effects.regular_regs[6], effects.regular_regs[7]
		);

		LOG_BLUE(
			" r8:0x%.8x  r9:0x%.8x r10:0x%.8x r11:0x%.8x",
			effects.regular_regs[8], effects.regular_regs[9],
			effects.regular_regs[10], effects.regular_regs[11]
		);

		LOG_BLUE(
			"r12:0x%.8x r13:0x%.8x r14:0x%.8x r15:0x%.8x",
			effects.regular_regs[12], effects.regular_regs[13],
			effects.regular_regs[14], effects.regular_regs[15]
		);
	}

	static void print_double_registers(const instruction_effects &effects) {
		LOG_BLUE(
			" d0:0x%.16llx  d1:0x%.16llx  d2:0x%.16llx  d3:0x%.16llx",
			effects.double_regs[0], effects.double_regs[1],
			effects.double_regs[2], effects.double_regs[3]
		);

		LOG_BLUE(
			" d4:0x%.16llx  d5:0x%.16llx  d6:0x%.16llx  d7:0x%.16llx",
			effects.double_regs[4], effects.double_regs[5],
			effects.double_regs[6], effects.double_regs[7]
		);

		LOG_BLUE(
			" d8:0x%.16llx  d9:0x%.16llx d10:0x%.16llx d11:0x%.16llx",
			effects.double_regs[8], effects.double_regs[9],
			effects.double_regs[10], effects.double_regs[11]
		);

		LOG_BLUE(
			"d12:0x%.16llx d13:0x%.16llx d14:0x%.16llx d15:0x%.16llx",
			effects.double_regs[12], effects.double_regs[13],
			effects.double_regs[14], effects.double_regs[15]
		);

		LOG_BLUE(
			"d16:0x%.16llx d17:0x%.16llx d18:0x%.16llx d19:0x%.16llx",
			effects.double_regs[16], effects.double_regs[17],
			effects.double_regs[18], effects.double_regs[19]
		);

		LOG_BLUE(
			"d20:0x%.16llx d21:0x%.16llx d22:0x%.16llx d23:0x%.16llx",
			effects.double_regs[20], effects.double_regs[21],
			effects.double_regs[22], effects.double_regs[23]
		);

		LOG_BLUE(
			"d24:0x%.16llx d25:0x%.16llx d26:0x%.16llx d27:0x%.16llx",
			effects.double_regs[24], effects.double_regs[25],
			effects.double_regs[26], effects.double_regs[27]
		);

		LOG_BLUE(
			"d28:0x%.16llx d29:0x%.16llx d30:0x%.16llx d31:0x%.16llx",
			effects.double_regs[28], effects.double_regs[29],
			effects.double_regs[30], effects.double_regs[31]
		);
	}

	static void print_diff(const char *desc0, const char *desc1, const instruction_effects &base, const instruction_effects &e0, const instruction_effects &e1) {
		std::vector<std::tuple<unsigned, u32_t, u32_t>> rr_diffs;
		std::vector<std::tuple<unsigned, u64_t, u64_t>> dr_diffs;

		if (e0.cpsr != e1.cpsr) {
			LOG_RED("%-14s: %s", "original", cpsr_to_string(base.cpsr).c_str());
			LOG_RED("%-14s: %s", desc0, cpsr_to_string(e0.cpsr).c_str());
			LOG_RED("%-14s: %s", desc1, cpsr_to_string(e1.cpsr).c_str());
		}

		for (unsigned i = 0; i < N_REGULAR_REGS; i++) {
			if (e0.regular_regs[i] != e1.regular_regs[i]) {
				auto entry = std::make_tuple(i, e0.regular_regs[i], e1.regular_regs[i]);
				rr_diffs.push_back(entry);
			}
		}

		for (unsigned i = 0; i < N_DOUBLE_REGS; i++) {
			if (e0.double_regs[i] != e1.double_regs[i]) {
				auto entry = std::make_tuple(i, e0.double_regs[i], e1.double_regs[i]);
				dr_diffs.push_back(entry);
			}
		}

		if (!rr_diffs.empty()) {
			LOG_RED("%-14s  %-14s  %-14s", "original", desc0, desc1);

			unsigned reg_no;
			u32_t val0, val1;
			for (const auto &diff : rr_diffs) {
				std::tie(reg_no, val0, val1) = diff;
				LOG_RED("r%-2u:0x%.8x  r%-2u:0x%.8x  r%-2u:0x%.8x", reg_no, base.regular_regs[reg_no], reg_no, val0, reg_no, val1);
			}

			instruction_effects::print_regular_registers(base);
		}

		if (!dr_diffs.empty()) {
			LOG_BLUE("Double registers differences:");

			unsigned reg_no;
			u64_t val0, val1;
			for (const auto &diff : dr_diffs) {
				std::tie(reg_no, val0, val1) = diff;
				LOG_RED("r%-2u:0x%.16llx != r%-2u:0x%.16llx", reg_no, val0, reg_no, val1);
			}

			instruction_effects::print_double_registers(base);
		}
	}
};

namespace RegisterInitPolicy {
	struct Zero {
		template <typename T>
		void initialize_registers(T &registers) {
			registers = {};
		}
	};

	template <unsigned initial_value=0>
	struct Inc {
		template <typename T>
		void initialize_registers(T &registers) {
			using integer_type = typename T::value_type;
			integer_type val = initial_value;
			std::generate_n(registers.begin(), registers.size(), [&val] {
				return val++;
			});
		}
	};

	struct Min {
		template <typename T>
		void initialize_registers(T &registers) {
			using integer_type = typename T::value_type;
			std::generate_n(registers.begin(), registers.size(), [] {
				return std::numeric_limits<integer_type>::min();
			});
		}
	};

	struct Max {
		template <typename T>
		void initialize_registers(T &registers) {
			using integer_type = typename T::value_type;
			std::generate_n(registers.begin(), registers.size(), [] {
				return std::numeric_limits<integer_type>::max();
			});
		}
	};

	struct Prime {
		template <typename T>
		void initialize_registers(T &registers) {
			using integer_type = typename T::value_type;
			std::array<integer_type, 32> primes = {
				2, 3, 5, 7, 11, 13, 17, 19,
				23, 29, 31, 37, 41, 43, 47,
				53, 59, 61, 67, 71, 73, 79,
				83, 89, 97, 101, 103, 107,
				109, 113, 127, 131
			};

			std::copy_n(std::begin(primes), registers.size(), std::begin(registers));
		}
	};

	struct Random {
		template <typename T>
		void initialize_registers(T &registers) {
			using integer_type = typename T::value_type;

			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<integer_type> dis(
				std::numeric_limits<integer_type>::min(),
				std::numeric_limits<integer_type>::max()
			);

			std::generate_n(registers.begin(), registers.size(), [&dis, &gen] {
				return dis(gen);
			});
		}
	};
}

class InstructionInspector {
public:
	virtual bool run(ARMMode mode, uint32_t opcode) = 0;
	virtual void reset() = 0;
	virtual instruction_effects effects() = 0;

protected:
	// Address of code scratch area.
	constexpr static uintptr_t m_base = 0xcafe0000;
	constexpr static size_t m_base_size = 4096;

	// Address of our stack.
	constexpr static uintptr_t m_stack_base = 0x44440000;
	constexpr static size_t m_stack_size = 4096;
	constexpr static size_t m_stack_alignment = 8;
};

template <typename RegInitPolicy>
class UnicornInstructionInspector: public InstructionInspector, public RegInitPolicy {
	using RegInitPolicy::initialize_registers;

public:
	UnicornInstructionInspector() {
		// Create an ARM cpu.
		uc_open(UC_ARCH_ARM, UC_MODE_ARM, &m_engine);

		// Create a scratch area for code and a stack.
		uc_mem_map(m_engine, m_base, m_base_size, UC_PROT_ALL);
		uc_mem_map(m_engine, m_stack_base, m_stack_size, UC_PROT_READ | UC_PROT_WRITE);

		// Generate special values for registers.
		std::array<u32_t, 16> u32_values;
		std::array<u64_t, 32> f64_values;

		initialize_registers(u32_values);
		initialize_registers(f64_values);

		// Initialize SP & PC.
		u32_values[13] = m_stack_base + m_stack_size - m_stack_alignment;
		u32_values[15] = m_base;

		// Initialize CPSR.
		uint32_t cpsr_val = INITIAL_CPSR_VALUE;
		uc_reg_write(m_engine, UC_ARM_REG_CPSR, &cpsr_val);

		// Write the test values.
		uc_reg_write_batch(m_engine, u32_values.data());
		uc_reg_write_batch(m_engine, f64_values.data());

		// Create a backup context for later fast restoration.
		uc_context_alloc(m_engine, &m_context);
		uc_context_save(m_engine, m_context);
	}

	~UnicornInstructionInspector() {
		uc_context_free(m_context);
		uc_close(m_engine);
	}

	bool run(ARMMode mode, uint32_t opcode) override {
		// Write the instruction and emulate it.
		uc_mem_write(m_engine, m_base, &opcode, sizeof(opcode));

		// Emulate.
		uc_err err = uc_emu_start(m_engine, m_base, m_base + sizeof(opcode) - 1, 0, 1);
		if (err != UC_ERR_OK) {
			return false;
		}

		return true;
	}

	instruction_effects effects() override {
		instruction_effects effects;
		uc_reg_read(m_engine, UC_ARM_REG_CPSR, &effects.cpsr);
		uc_reg_read_batch(m_engine, effects.regular_regs.data());
		uc_reg_read_batch(m_engine, effects.double_regs.data());
		return effects;
	}

	void reset() override {
		uc_context_restore(m_engine, m_context);
		uc_mem_write(m_engine, m_base, &zero[0], zero.size());

		// Make sure unicorn does the right thing with CPSR.
		uint32_t cpsr = 0;
		uc_reg_read(m_engine, UC_ARM_REG_CPSR, &cpsr);
		assert(cpsr == INITIAL_CPSR_VALUE && "Something went wrong with the value of CPSR.");
	}

private:
	uc_engine *m_engine;
	uc_context *m_context;

	std::array<uint8_t, m_base_size> zero{};
};

template <typename RegInitPolicy>
class REToolsInstructionInspector: public InstructionInspector, public RegInitPolicy {
	std::unique_ptr<ARMEmulator> m_emulator;
	std::unique_ptr<ConcreteMemory> m_memory;
	std::unique_ptr<ARMContext> m_context;
	ARMContext m_saved_context;

	using RegInitPolicy::initialize_registers;

public:
	REToolsInstructionInspector() {
		m_memory = std::make_unique<ConcreteMemory>();
		m_context = std::make_unique<ARMContext>(m_memory.get());
		m_emulator = std::make_unique<ARMEmulator>(m_context.get(), m_memory.get(), ARMMode_ARM);

		// Create a scratch area for code and a stack.
		m_memory->map(m_base, m_base_size, 0);
		m_memory->map(m_stack_base, m_stack_size, 0);

		// Generate special values for registers.
		std::array<u32_t, 16> u32_values;
		std::array<u64_t, 32> f64_values;
		initialize_registers(u32_values);
		initialize_registers(f64_values);

		// Initialize SP & PC.
		u32_values[13] = m_stack_base + m_stack_size - m_stack_alignment;
		u32_values[15] = m_base;

		m_context->CPSR = INITIAL_CPSR_VALUE;
		m_context->setCoreRegisters(u32_values);
		m_context->setDoubleRegisters(f64_values);
		m_saved_context = *m_context;
	}

	~REToolsInstructionInspector() {
	}

	bool run(ARMMode mode, uint32_t opcode) override {
		m_context->SelectInstrSet(mode);
		m_context->setRegister(Register::ARM_REG_PC, m_base);
		m_memory->write_value(m_base, opcode);
		m_emulator->start(1);
		return true;
	}

	instruction_effects effects() override {
		instruction_effects effects;
		effects.cpsr = m_context->CPSR;
		effects.regular_regs = m_context->getCoreRegisters();
		effects.double_regs = m_context->getDoubleRegisters();
		return effects;
	}

	void reset() override {
		*m_context = m_saved_context;
	}
};

template <typename RegInitPolicy>
class HardwareInstructionInspector: public InstructionInspector, public RegInitPolicy {
public:
	HardwareInstructionInspector() {
	}

	~HardwareInstructionInspector() {
	}

	bool run(ARMMode mode, uint32_t opcode) override {
		return false;
	}

	instruction_effects effects() override {
		return {};
	}

	void reset() override {
	}
};

class InstructionGenerator {
public:
	InstructionGenerator(size_t start, size_t finish, size_t n) {
		m_idx = start;
		m_number = n;
		m_cnt = 0;
	}

	bool get(uint32_t &instruction) {
		if (m_cnt == m_number) {
			// Reset instruction counter.
			m_cnt = 0;

			// Advance to the next instruction.
			m_idx++;
			if (m_idx == m_finish) {
				instruction = 0;
				return false;
			}

			m_mask = m_opcodes[m_idx].mask;
			m_value = m_opcodes[m_idx].value;
		}

		// Increment instruction counter.
		m_cnt++;

		instruction = generate();
		return true;
	}

protected:
	virtual uint32_t generate() = 0;

	size_t m_idx;
	size_t m_cnt;
	size_t m_finish;
	size_t m_number;

	ARMOpcode *m_opcodes;
	uint32_t m_mask;
	uint32_t m_value;
	uint32_t m_size;
};

struct ARMInstructionGenerator: public InstructionGenerator {
public:
	ARMInstructionGenerator(size_t start, size_t finish, size_t n) : InstructionGenerator(start, finish, n) {
		if (start == finish || finish > n_arm_opcodes) {
			finish = n_arm_opcodes - 1;
		}

		// Set the correct opcode table pointer.
		m_opcodes = arm_opcodes;

		m_finish = finish;
		m_mask = m_opcodes[m_idx].mask;
		m_value = m_opcodes[m_idx].value;
	}

private:
	uint32_t generate() override {
		// We avoid generating condition codes of 0b1111.
		uint32_t instruction = get_masked_random(m_mask, m_value);
		if (get_bit(m_mask, 28) == 0) {
			instruction &= 0xefffffff;
		}

		// Make the instruction unconditional.
		instruction |= 0xe0000000;
		return instruction;
	}
};

struct ThumbInstructionGenerator: public InstructionGenerator {
public:
	ThumbInstructionGenerator(size_t start, size_t finish, size_t n) : InstructionGenerator(start, finish, n) {
		if (start == finish || finish > n_thumb_opcodes) {
			finish = n_thumb_opcodes - 1;
		}

		// Set the correct opcode table pointer.
		m_opcodes = thumb_opcodes;

		m_finish = finish;
		m_mask = m_opcodes[m_idx].mask;
		m_value = m_opcodes[m_idx].value;
		m_size = m_opcodes[m_idx].ins_size == eSize16 ? 16 : 32;
	}

private:
	uint32_t generate() override {
		uint32_t instruction = get_masked_random(m_mask, m_value, m_size);
		return instruction;
	}
};

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
	unsigned start = std::stoi(argv[2]);
	unsigned finish = std::stoi(argv[3]);
	unsigned mode = std::stoi(argv[4]);
	char *path = argv[5];

	// Create 'N' instruction inspectors.
	UnicornInstructionInspector<RegisterInitPolicy::Inc<0xcafe0000>> unicorn_inspector;
	REToolsInstructionInspector<RegisterInitPolicy::Inc<0xcafe0000>> retools_inspector;

	// Get the initial context values.
	auto unicorn_base_context = unicorn_inspector.effects();
	auto retools_base_context = retools_inspector.effects();

	// Verify that they match.
	if (unicorn_base_context != retools_base_context) {
		LOG_ERR("Initial instrution inspectors contexts do not match.");
		instruction_effects::print(unicorn_base_context);
		instruction_effects::print(retools_base_context);

		LOG_DEBUG("Differences:");
		instruction_effects::print_diff("unicorn", "retools", unicorn_base_context, unicorn_base_context, retools_base_context);
		exit(-1);
	}

	LOG_INFO("Testing random instructions from %u to %u, %u times in mode %s.", start, finish, n, !mode ? "ARM" : "THUMB");
	LOG_INFO("Saving results to '%s'", path);

	// Create the right generator.
	InstructionGenerator *gen = mode == 0 ?
		static_cast<InstructionGenerator *>(new ARMInstructionGenerator(start, finish, n)) :
		static_cast<InstructionGenerator *>(new ThumbInstructionGenerator(start, finish, n));

	// Generate random opcodes.
	uint32_t op_code;
	while (gen->get(op_code)) {
		LOG_INFO("");
		LOG_INFO("%-10s %-30s %-30s", "opcode", "retools", "capstone");
		LOG_INFO("0x%.8x %-30s %-30s", op_code, retools_disassemble(op_code, 0).c_str(), capstone_disassemble(op_code, 0).c_str());

		if (!unicorn_inspector.run(ARMMode_ARM, op_code)) {
			continue;
		}

		if (!retools_inspector.run(ARMMode_ARM, op_code)) {
			continue;
		}

		// Collect the effects.
		auto r0 = unicorn_inspector.effects();
		auto r1 = retools_inspector.effects();

		// Reset to initial state.
		unicorn_inspector.reset();
		retools_inspector.reset();

		// Check if effects differs.
		if (r0 != r1) {
			instruction_effects::print_diff("unicorn", "retools", unicorn_base_context, r0, r1);
		}
	}

	return 0;
}
