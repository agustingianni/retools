#include <iostream>
#include <random>
#include <limits>
#include <cassert>
#include <memory>

#include "utilities/Utilities.h"
#include "disassembly/arm/ARMDisassembler.h"
#include "disassembly/arm/gen/ARMDecodingTable.h"

extern "C" {
#include <darm.h>
}

#include <capstone/capstone.h>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

using namespace std;
using namespace Disassembler;

string normalize_numbers(string input) {
	return input;

	boost::regex re("#[1-9][0-9]*");
	boost::cmatch matches;
	boost::regex_search(input.c_str(), matches, re);

	string out = string(input);

	cout << "IN " << input << endl;

	for (unsigned i = 0; i < matches.size(); i++) {
		string match(matches[i].first, matches[i].second);
		if (!match.size())
			continue;

		unsigned integer = 0;

		try {
			integer = std::stoul(match.substr(1));
		} catch (exception& e) {
			// cout << "Error with: 0x" << hex << match.substr(1) << ": " << e.what() << '\n';
			continue;
		}

		boost::replace_all(out, match, "#" + integer_to_string(integer));
	}

	cout << "OU " << out << endl;

	return out;
}

string normalize_registers(string input) {
	boost::replace_all(input, "r9", "sb");
	boost::replace_all(input, "r10", "sl");
	boost::replace_all(input, "r11", "fp");
	boost::replace_all(input, "r12", "ip");
	return input;
}

string normalize_string(string input) {
	string tmp = normalize_numbers(normalize_registers(input));
	boost::algorithm::to_lower(tmp);
	return tmp;
}

template<class T> T get_random_int() {
	static random_device rd;
	uniform_int_distribution<T> uniform_dist(numeric_limits<T>::min(), numeric_limits<T>::max());
	return uniform_dist(rd);
}

uint32_t get_masked_random_arm(uint32_t mask, uint32_t value, uint32_t size = 32) {
	uint32_t r = get_random_int<uint32_t>();

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

unsigned test_thumb() {
	Disassembler::ARMDisassembler dis;
	return 0;
}

string objdump_disassemble(uint32_t opcode, unsigned mode) {
	string command = "python ../tests/manual.py " + std::to_string(opcode) + (mode == 0 ? " ARM" : " THUMB");
	string output = exec_get_output(command);
	return output.substr(0, output.size() - 1);
}

string capstone_disassemble(uint32_t op_code, cs_mode mode) {
	csh handle;
	cs_insn *insn;
	size_t count;
	string ret = "INVALID";

	// cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);
	cs_open(CS_ARCH_ARM, mode, &handle);
	{
		count = cs_disasm_ex(handle, (unsigned char *) &op_code, sizeof(op_code), 0, 0, &insn);
		if (count) {
			ret = string(insn[0].mnemonic) + " " + string(insn[0].op_str);
			cs_free(insn, count);
		}
	}
	cs_close(&handle);

	return ret;
}

string darm_disassemble(uint32_t opcode, unsigned mode) {
	string ret = "INVALID";
	darm_t d;
	char str[1024];
	memset(str, 0, sizeof(str));

	if (mode == 0) {
		if (darm_armv7(&d, opcode) != -1) {
			darm_string(&d, str);
			ret = string(str);
		}
	} else {
		if (darm_thumb(&d, opcode & 0xffff, opcode >> 16) != -1) {
			darm_string(&d, str);
			ret = string(str);
		}
	}

	return ret;
}

string retools_disassemble(uint32_t opcode, unsigned mode) {
	ARMDisassembler dis(ARMv7VE);
	shared_ptr<ARMInstruction> ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	return ins->toString();
}

unsigned test_arm(unsigned n = 100, unsigned start = 0, unsigned finish = n_arm_opcodes, bool show = false) {
	ARMDisassembler dis;

	if (start == finish) {
		finish = n_arm_opcodes;
	}

	for (unsigned i = start; i < finish; ++i) {
		if (i == 9)
			continue;

		unsigned total = n;
		unsigned match = 0;
		unsigned fail = 0;
		unsigned invalid = 0;
		unsigned to_string_missing = 0;
		unsigned todo = 0;

		uint32_t mask = arm_opcodes[i].mask;
		uint32_t value = arm_opcodes[i].value;
		uint32_t op_code;

		for (unsigned j = 0; j < total; ++j) {
			op_code = get_masked_random_arm(mask, value);
			// op_code = (op_code & 0x0fffffff) | 0xe0000000;

			string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_ARM));
			string darm = normalize_string(darm_disassemble(op_code, 0));
			string retools = normalize_string(retools_disassemble(op_code, 0));
			string objdump = normalize_string(objdump_disassemble(op_code, 0));

//			printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
//			printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
//			printf("darm: 0x%.8x = %40s\n", op_code, darm.c_str());
//			printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
//			continue;

			if (capstone == retools || darm == retools || objdump == retools) {
				match++;
				continue;
			}

			// Avoid flagging "adc r4, r6, r2, lsl #0" != "adc r4, r6, r2"
			if (retools.find(", lsl #0") != string::npos) {
				string tmp = retools.substr(0, retools.size() - strlen(", lsl #0"));
				if (capstone == tmp || darm == tmp) {
					match++;
					continue;
				}
			}

			if (retools.find("todo_") != string::npos) {
				todo++;
				printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
				printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
			} else if (retools == "to_string_missing") {
				to_string_missing++;
				printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
				printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
			} else if (capstone == "invalid") {
				invalid++;
			} else if (objdump.find("invalid")) {
				// Avoid bfi r2, r6, (invalid: 21:14)
				invalid++;
			} else {
				fail++;
			}

			if (show && false) {
				printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
				printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
				printf("darm: 0x%.8x = %40s\n", op_code, darm.c_str());
				printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
			}
		}

		printf("marginal: %6.2f%% ok: %6.2f%% todo: %4d match: %4d fail: %4d invalid: %4d to_string: %4d name: %50s enc: %4d n: %d\n",
				(match + invalid) * 100.0 / total, match * 100.0 / total, todo, match, fail, invalid, to_string_missing,
				arm_opcodes[i].name, arm_opcodes[i].encoding, i);
	}

	return 0;
}

unsigned test_thumb(unsigned n = 100, unsigned start = 0, unsigned finish = n_thumb_opcodes, bool show = false) {
	ARMDisassembler dis;

	for (unsigned i = start; i < finish; ++i) {
		unsigned total = n;
		unsigned match = 0;
		unsigned fail = 0;
		unsigned invalid = 0;
		unsigned to_string_missing = 0;

		uint32_t mask = thumb_opcodes[i].mask;
		uint32_t value = thumb_opcodes[i].value;
		uint32_t size = thumb_opcodes[i].ins_size == eSize16 ? 16 : 32;
		uint32_t op_code;

		for (unsigned j = 0; j < total; ++j) {
			op_code = get_masked_random_arm(mask, value, size);
			op_code = (op_code & 0xffff) << 16 | (op_code >> 16);

			string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_THUMB));
			string darm = normalize_string(darm_disassemble(op_code, 1));
			string retools = normalize_string(retools_disassemble(op_code, 1));

			if (capstone == retools || darm == retools) {
				match++;
				continue;
			}

			if (retools == "to_string_missing" || retools.find("todo_") != string::npos) {
				to_string_missing++;
				continue;

				printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
				printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
				printf("darm: 0x%.8x = %40s\n\n", op_code, darm.c_str());

				continue;
			}

			fail++;

			if (show) {
				printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
				printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
				printf("darm: 0x%.8x = %40s\n\n", op_code, darm.c_str());
			}
		}

		printf(
				"marginal: %6.2f%% ok: %6.2f%% match: %4d fail: %4d invalid: %4d to_string_missing: %4d name: %50s encoding: %4d n: %d\n",
				(match + invalid) * 100.0 / total, match * 100.0 / total, match, fail, invalid, to_string_missing,
				arm_opcodes[i].name, arm_opcodes[i].encoding, i);
	}

	return 0;
}

int main(int argc, char **argv) {
	cout << "Executing 'instruction_fuzz' test" << endl;

	unsigned n = std::stoi(argv[1]);
	unsigned i = std::stoi(argv[2]);
	unsigned j = std::stoi(argv[3]);

	test_arm(n, i, j, true);
	// test_thumb(10, i, j, true);
	return 0;

	uint32_t op_code = 0xe2ac0b03;
	string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_ARM));
	string darm = normalize_string(darm_disassemble(op_code, 0));
	string retools = normalize_string(retools_disassemble(op_code, 0));
	string objdump = normalize_string(objdump_disassemble(op_code, 0));
	printf("MANUAL:\nreto: 0x%.8x = %40s\n", op_code, retools.c_str());
	printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
	printf("darm: 0x%.8x = %40s\n", op_code, darm.c_str());
	printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
	return 0;
}
