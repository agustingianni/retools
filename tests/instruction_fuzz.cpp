#include <arm/ARMDisassembler.h>
#include <arm/gen/ARMDecodingTable.h>
#include <iostream>
#include <limits>
#include <cassert>
#include <cstdio>
#include <boost/algorithm/string.hpp>

#include "Utilities.h"
#include "test_utils.h"

namespace darm {
extern "C" {
#include <darm.h>
}
}

#include <capstone/capstone.h>

using namespace std;
using namespace Disassembler;

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

struct InvalidChar {
    bool operator()(char c) const {
        return !isprint((unsigned)c);
    }
};

string darm_disassemble(uint32_t opcode, unsigned mode) {
	string ret = "INVALID";
	darm::darm_t d;
	darm::darm_str_t str;

	if (mode == 0) {
		if (darm_armv7_disasm(&d, opcode) != -1) {
			ret = darm_str(&d, &str) < 0 ? "INVALID" : string(str.total);
		}
	} else {
		if (darm_thumb2_disasm(&d, opcode & 0xffff, opcode >> 16) != -1) {
			ret = darm_str(&d, &str) < 0 ? "INVALID" : string(str.total);
		}
	}

	ret.erase(std::remove_if(ret.begin(), ret.end(), InvalidChar()), ret.end());
	return ret;
}

string retools_disassemble(uint32_t opcode, unsigned mode, string &decoder) {
	ARMDisassembler dis(ARMvAll);
	ARMInstruction ins = dis.disassemble(opcode, mode == 0 ? ARMMode_ARM : ARMMode_Thumb);
	decoder = ins.m_decoded_by;
	return ins.toString();
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

		fprintf(file, "    {\n");
		fprintf(file, "      \"name\"     : \"%s\",\n", arm_opcodes[i].name);
		fprintf(file, "      \"mask\"     : %u,\n", arm_opcodes[i].mask);
		fprintf(file, "      \"value\"    : %u,\n", arm_opcodes[i].value);
		fprintf(file, "      \"size\"     : %u,\n", 32);
		fprintf(file, "      \"encoding\" : \"%s\",\n", ARMEncodingToString(arm_opcodes[i].encoding));
		fprintf(file, "      \"results\"  :\n");
		fprintf(file, "      [\n");

		for (unsigned j = 0; j < n; ++j) {
			op_code = get_masked_random(mask, value);

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
		finish = n_thumb_opcodes - 1;
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
			op_code = get_masked_random(mask, value, size);

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
