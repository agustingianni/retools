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

	op_code = ((op_code & 0xffff) << 16) | (op_code >> 16);

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

	opcode = ((opcode & 0xffff) << 16) | (opcode >> 16);

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
	ARMDisassembler dis((ARMVariants) ((int) ARMv7 | (int) AdvancedSIMD));
	shared_ptr<ARMInstruction> ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	return ins->toString();
}

bool skip_instruction(const string &n1, const string &n2, const string &n3) {
	// Skip this instructions as they are correct but the output format does not match.
	const char *skip_ins[] = {"bfi", "ldrh", "ldrsb", "ldrd", "ldrsh", "ldc",
		"stc", "ssat", "pkh", "bfc", "sub", "lsl", "ldr", "vstr", "str", "usat", "udf", "msr"};
	const unsigned skip_ins_size = sizeof(skip_ins) / sizeof(skip_ins[0]);
	for(unsigned i = 0; i < skip_ins_size; ++i) {
		if (n1.find(skip_ins[i]) != string::npos && n2.find(skip_ins[i]) != string::npos ) {
			return true;
		}
	}

	if (n2.find("cdp2")!= string::npos) {
		return true;
	}

	if (n1.find("add") != string::npos && n2.find("adr") != string::npos) {
		return true;
	}

	// popvs {r1} == ldrvs r1, [sp], #4
	if (n1.find("ldr") != string::npos && n2.find("pop") != string::npos) {
		return true;
	}

	// pushhs {r0} == strhs r0, [sp, #-4]!
	if (n1.find("str") != string::npos && n2.find("push") != string::npos) {
		return true;
	}

	// Avoid flagging "adc r4, r6, r2, lsl #0" != "adc r4, r6, r2"
	if (n2.find(", lsl #0") != string::npos) {
		string tmp = n2.substr(0, n2.size() - strlen(", lsl #0"));
		if (n1 == tmp || n3 == tmp) {
			return true;
		}
	}

	return false;
}

unsigned test_arm(unsigned n, unsigned start, unsigned finish, bool show) {
	ARMDisassembler dis;

	if (start == finish) {
		finish = n_arm_opcodes;
	}

	for (unsigned i = start; i < finish; ++i) {
		unsigned total = n;
		unsigned match = 0;
		unsigned fail = 0;
		unsigned invalid = 0;
		unsigned to_string_missing = 0;
		unsigned todo = 0;

		uint32_t mask = arm_opcodes[i].mask;
		uint32_t value = arm_opcodes[i].value;
		uint32_t op_code;

		unsigned c = 0;
		for (unsigned j = 0; j < total; ++j) {
			op_code = get_masked_random_arm(mask, value);

			// We avoid generating condition codes of 0b1111.
			if (get_bit(mask, 28) == 0) {
				// printf("CACA: %.8x %.8x %.8x %.8x\n", mask ,value, op_code, op_code&0xefffffff);
				op_code &= 0xefffffff;
			}

			string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_ARM));
			string darm = normalize_string(darm_disassemble(op_code, 0));
			string retools = normalize_string(retools_disassemble(op_code, 0));
			// string objdump = normalize_string(objdump_disassemble(op_code, 0));

			// if (capstone == retools || darm == retools || objdump == retools) {
			if (capstone == retools || darm == retools) {
				match++;
				continue;
			}

			// Some instructions are a match but differ in the way they are displayed.
			if (skip_instruction(capstone, retools, darm)) {
				match++;
				continue;
			}

			if (retools.find("todo_") != string::npos) {
				todo++;
			} else if (retools == "to_string_missing") {
				to_string_missing++;
			// } else if (capstone == "invalid" || objdump.find("invalid")) {
			} else if (capstone == "invalid" || retools == "unpredictableinstruction" || retools == "unknown" || retools == "undefinedinstruction") {
				invalid++;
			} else {
				if (show && c++ < 10) {
					printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
					printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
					printf("darm: 0x%.8x = %40s\n\n", op_code, darm.c_str());
					// printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
				}

				fail++;
			}
		}

		if (fail) {
			printf("%6.2f%% | %6.2f%% -> match: %4d fail: %4d invalid: %4d todo: %4d to_string: %4d name: %50s enc: %4d n: %d\n",
				(match + invalid) * 100.0 / total,
				match * 100.0 / total,
				match,
				fail,
				invalid,
				todo,
				to_string_missing,
				arm_opcodes[i].name,
				arm_opcodes[i].encoding,
				i
			);
		}
	}

	return 0;
}

unsigned test_thumb(unsigned n, unsigned start, unsigned finish, bool show) {
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

		printf("m=%.8x v=%.8x s=%u n=\"%s\"\n",
			thumb_opcodes[i].mask,
			thumb_opcodes[i].value,
			size,
			thumb_opcodes[i].name
		);

		for (unsigned j = 0; j < total; ++j) {
			op_code = get_masked_random_arm(mask, value, size);
			// if (size == 32)
			// 	op_code = ((op_code & 0xffff) << 16) | (op_code >> 16);

			string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_THUMB));
			string darm = normalize_string(darm_disassemble(op_code, 1));
			string retools = normalize_string(retools_disassemble(op_code, 1));

			if (capstone == retools || darm == retools) {
				match++;
				continue;
			}

			printf("reto: 0x%.8x = %40s\n", op_code, retools.c_str());
			printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
			printf("darm: 0x%.8x = %40s\n\n", op_code, darm.c_str());
		}

		printf("%6.2f%% %6.2f%% match: %4d fail: %4d invalid: %4d to_string_missing: %4d name: %50s encoding: %4d n: %d\n",
				(match + invalid) * 100.0 / total, match * 100.0 / total, match, fail, invalid, to_string_missing,
				arm_opcodes[i].name, arm_opcodes[i].encoding, i);
	}

	return 0;
}

void gen_shit(unsigned i, unsigned j) {
	csh handle;
	cs_insn *insn;
	size_t count;
	string dis_caps, dis_retools;

	unsigned ok = 0, fail=0;

	ARMDisassembler dis(ARMv7);
	shared_ptr<ARMInstruction> ins;

	cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
	{
		for(unsigned opcode = i; opcode < j; opcode += 1) {
			count = cs_disasm_ex(handle, (unsigned char *) &opcode, sizeof(opcode), 0, 0, &insn);
			if (count) {
				// Capstones disassembly.
				dis_caps = string(insn[0].mnemonic) + " " + string(insn[0].op_str);

				// Our disassembly.
				ins = dis.disassemble(opcode, ARMMode_ARM);
				dis_retools = ins->toString();
				boost::algorithm::to_lower(dis_retools);

				if (dis_retools.find(", lsl #0") != string::npos) {
					dis_retools = dis_retools.substr(0, dis_retools.size() - strlen(", lsl #0"));
				}

				// if (dis_caps != dis_retools && dis_retools != "UnpredictableIns") {
				if (normalize_string(dis_caps) != normalize_string(dis_retools)
					&& dis_retools != "unpredictableinstruction"
					&& dis_retools != "unknown") {

					cout << "OPCODE  : " << hex << opcode << '\n';
					cout << "CAPSTONE: " << dis_caps << '\n';
					cout << "RETOOOLS: " << dis_retools << "\n\n";
				}

				ok++;
				cs_free(insn, count);
			} else {
				fail++;
			}
		}
	}
	cs_close(&handle);

	printf("fail=%u ok=%u\n", fail, ok);
}

// Traverse the table checking that a given entry at index 'i' matches another
// entry at index 'j' where 'j' < 'i'. This is to check the correctness of the
// decoding table. Most of the results of this test are false positives since
// each decoder has a SEE statement that makes de decoding procedure continue
// looking for the next decoder enty.
void test_decoding_table() {
	for (unsigned i = 0; i < n_arm_opcodes - 1; ++i) {
		bool print_h = false, print_f = false;

		for (unsigned j = 0; j < i; ++j) {
			if ((arm_opcodes[i].value & arm_opcodes[j].mask) == arm_opcodes[j].value) {
				if (!print_h) {
					printf("Instruction:\n  i=%3d m=0x%.8x v=0x%.8x e=%d n=\"%s\"\n",
						i,
						arm_opcodes[i].mask,
						arm_opcodes[i].value,
						arm_opcodes[i].encoding,
						arm_opcodes[i].name
					);

					print_h = true;
					print_f = true;
				}

				printf("  i=%3d m=0x%.8x v=0x%.8x e=%d n=\"%s\" %s\n",
					j,
					arm_opcodes[j].mask,
					arm_opcodes[j].value,
					arm_opcodes[j].encoding,
					arm_opcodes[j].name,
					i > j ? "*" : ""
				);
			}
		}

		if (print_f)
			puts("");
	}
}

// Print the representation under all the available disassemblers.
void test_manual_opcode(uint32_t op_code) {
	string capstone = normalize_string(capstone_disassemble(op_code, CS_MODE_ARM));
	string darm = normalize_string(darm_disassemble(op_code, 0));
	string retools = normalize_string(retools_disassemble(op_code, 0));
	string objdump = normalize_string(objdump_disassemble(op_code, 0));

	printf("MANUAL:\nreto: 0x%.8x = %40s\n", op_code, retools.c_str());
	printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
	printf("darm: 0x%.8x = %40s\n", op_code, darm.c_str());
	printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
}

int main(int argc, char **argv) {
	// test_decoding_table();
	// return 0;

	// test_manual_opcode(0xcafecafe);
	// return 0;

	cout << "Executing 'instruction_fuzz' test" << endl;

	unsigned n = std::stoi(argv[1]);
	unsigned i = std::stoi(argv[2]);
	unsigned j = std::stoi(argv[3]);
	unsigned k = std::stoi(argv[4]);

	test_thumb(n, i, j, k == 1 ? true : false);
	return 0;

	test_arm(n, i, j, k == 1 ? true : false);
	return 0;
}
