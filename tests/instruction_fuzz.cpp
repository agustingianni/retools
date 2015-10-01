#include <arm/ARMDisassembler.h>
#include <arm/gen/ARMDecodingTable.h>
#include <iostream>
#include <random>
#include <limits>
#include <cassert>
#include <memory>
#include <cstdio>
#include <boost/algorithm/string.hpp>

#include "Utilities.h"

extern "C" {
#include <darm.h>
}

#include <capstone/capstone.h>

using namespace std;
using namespace Disassembler;

template<class T> T get_random_int() {
	static random_device rd;
	uniform_int_distribution<T> uniform_dist(numeric_limits<T>::min(), numeric_limits<T>::max());
	return uniform_dist(rd);
}

uint32_t get_masked_random_arm(uint32_t mask, uint32_t value, uint32_t size = 32) {
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

	cs_open(CS_ARCH_ARM, mode, &handle);
	{
		count = cs_disasm(handle, (unsigned char *) &op_code, sizeof(op_code), 0, 0, &insn);
		if (count) {
			ret = string(insn[0].mnemonic) + " " + string(insn[0].op_str);
			cs_free(insn, count);
		}
	}
	cs_close(&handle);

	return ret;
}

string darm_disassemble(uint32_t opcode, unsigned mode) {
	return "AVOID";
	string ret = "INVALID";
	darm_t d;
	darm_str_t str;

	if (mode == 0) {
		if (darm_armv7_disasm(&d, opcode) != -1) {
			darm_str(&d, &str);
			ret = string(str.total);
		}
	} else {
		if (darm_thumb2_disasm(&d, opcode & 0xffff, opcode >> 16) != -1) {
			darm_str(&d, &str);
			ret = string(str.total);
		}
	}

	return ret;
}

string retools_disassemble(uint32_t opcode, unsigned mode, string &decoder) {
	ARMDisassembler dis(ARMvAll);
	shared_ptr<ARMInstruction> ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	decoder = ins->m_decoded_by;
	return ins->toString();
}

void test_arm(unsigned n, unsigned start, unsigned finish, FILE *file) {
	uint32_t mask;
	uint32_t value;
	uint32_t op_code;

	if (start == finish || finish > n_arm_opcodes) {
		finish = n_arm_opcodes;
	}

	for (unsigned i = start; i < finish; ++i) {
		mask = arm_opcodes[i].mask;
		value = arm_opcodes[i].value;

		fprintf(file, "    {\n");
		fprintf(file, "      \"name\"     : \"%s\",\n", arm_opcodes[i].name);
		fprintf(file, "      \"mask\"     : %u,\n", arm_opcodes[i].mask);
		fprintf(file, "      \"value\"    : %u,\n", arm_opcodes[i].value);
		fprintf(file, "      \"size\"     : %u,\n", 32);
		fprintf(file, "      \"encoding\" : \"%s\",\n", ARMEncodingToString(arm_opcodes[i].encoding));
		fprintf(file, "      \"results\"  :\n");
		fprintf(file, "      [\n");

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random_arm(mask, value);

			// We avoid generating condition codes of 0b1111.
			if (get_bit(mask, 28) == 0) {
				op_code &= 0xefffffff;
			}

			string decoder;
			string capstone = capstone_disassemble(op_code, CS_MODE_ARM);
			string darm = darm_disassemble(op_code, 0);
			string retools = retools_disassemble(op_code, 0, decoder);

			fprintf(file, "        {\n");
			fprintf(file, "          \"opcode\"  : %u,\n", op_code);
			fprintf(file, "          \"decoder\" : \"%s\",\n", decoder.c_str());
			fprintf(file, "          \"reto\"    : \"%s\",\n", retools.c_str());
			fprintf(file, "          \"caps\"    : \"%s\",\n", capstone.c_str());
			fprintf(file, "          \"darm\"    : \"%s\"\n", darm.c_str());
			fprintf(file, "        }");
			fprintf(file, (j == n - 1) ? "\n" : ",\n");
		}

		fprintf(file, "      ]\n");
		fprintf(file, "    }");
		fprintf(file, (i == finish - 1) ? "\n" : ",\n");
	}
}

void test_thumb(unsigned n, unsigned start, unsigned finish, FILE *file) {
	uint32_t mask;
	uint32_t value;
	uint32_t size;
	uint32_t op_code;

	if (start == finish || finish > n_thumb_opcodes) {
		finish = n_thumb_opcodes;
	}

	for (unsigned i = start; i < finish; ++i) {
		mask = thumb_opcodes[i].mask;
		value = thumb_opcodes[i].value;
		size = thumb_opcodes[i].ins_size == eSize16 ? 16 : 32;

		fprintf(file, "    {\n");
		fprintf(file, "      \"name\"     : \"%s\",\n", thumb_opcodes[i].name);
		fprintf(file, "      \"mask\"     : %u,\n", thumb_opcodes[i].mask);
		fprintf(file, "      \"value\"    : %u,\n", thumb_opcodes[i].value);
		fprintf(file, "      \"size\"     : %u,\n", thumb_opcodes[i].ins_size == eSize16 ? 16 : 32);
		fprintf(file, "      \"encoding\" : \"%s\",\n", ARMEncodingToString(thumb_opcodes[i].encoding));
		fprintf(file, "      \"results\"  :\n");
		fprintf(file, "      [\n");

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random_arm(mask, value, size);

			unsigned caps_op_code = size == 32 ? ((op_code & 0xffff) << 16 ) | (op_code >> 16) : op_code;
			// unsigned darm_op_code = size == 16 ? ((op_code & 0xffff) << 16 ) | (op_code >> 16) : op_code;

			string decoder;
			string capstone = capstone_disassemble(caps_op_code, CS_MODE_THUMB);
			string darm = darm_disassemble(op_code, 1);
			string retools = retools_disassemble(op_code, 1, decoder);

			fprintf(file, "        {\n");
			fprintf(file, "          \"opcode\"  : %u,\n", op_code);
			fprintf(file, "          \"decoder\" : \"%s\",\n", decoder.c_str());
			fprintf(file, "          \"reto\"    : \"%s\",\n", retools.c_str());
			fprintf(file, "          \"caps\"    : \"%s\",\n", capstone.c_str());
			fprintf(file, "          \"darm\"    : \"%s\"\n", darm.c_str());
			fprintf(file, "        }");
			fprintf(file, (j == n - 1) ? "\n" : ",\n");
		}

		fprintf(file, "      ]\n");
		fprintf(file, "    }");
		fprintf(file, (i == finish - 1) ? "\n" : ",\n");
	}
}

void test(unsigned n, unsigned start, unsigned finish, unsigned mode, char *path) {
	FILE *file = fopen(path, "w");
	assert(file && "Could not open output file.");

	fprintf(file, "{\n");
	fprintf(file, "  \"mode\" : \"%s\",\n", mode == 0 ? "ARM" : "THUMB");
	fprintf(file, "  \"tests\" : \n");
	fprintf(file, "  [\n");

	if (mode == 0) {
		test_arm(n, start, finish, file);
	} else {
		test_thumb(n, start, finish, file);
	}

	fprintf(file, "  ]\n");
	fprintf(file, "}\n");

	fclose(file);
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
			count = cs_disasm(handle, (unsigned char *) &opcode, sizeof(opcode), 0, 0, &insn);
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
	string decoder;
	string capstone = capstone_disassemble(op_code, CS_MODE_ARM);
	string darm = darm_disassemble(op_code, 0);
	string retools = retools_disassemble(op_code, 0, decoder);
	string objdump = objdump_disassemble(op_code, 0);

	printf("MANUAL:\nreto: 0x%.8x = %40s\n", op_code, retools.c_str());
	printf("caps: 0x%.8x = %40s\n", op_code, capstone.c_str());
	printf("darm: 0x%.8x = %40s\n", op_code, darm.c_str());
	printf("objd: 0x%.8x = %40s\n\n", op_code, objdump.c_str());
}

int main(int argc, char **argv) {
	unsigned n = std::stoi(argv[1]);
	unsigned i = std::stoi(argv[2]);
	unsigned j = std::stoi(argv[3]);
	unsigned k = std::stoi(argv[4]);
	char *path = argv[5];

	test(n, i, j, k, path);
	return 0;
}
