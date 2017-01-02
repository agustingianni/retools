/*
 * ARMDisassembler.h
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#ifndef ARMDISASSEMBLER_H_
#define ARMDISASSEMBLER_H_

#include <functional>
#include <iostream>
#include <cassert>
#include <string>

#include "ARMArch.h"
// #include "gen/ARMInstructionFields.h"

class ARMDecoder;

#define IS_THUMB_VFP_OR_ASIMD_1(op) ((op & 0xef000e00) == 0xee000a00) // THUMB Floating-point data-processing instructions
#define IS_THUMB_VFP_OR_ASIMD_2(op) ((op & 0xef000000) == 0xef000000) // THUMB Advanced SIMD data-processing instructions
#define IS_THUMB_VFP_OR_ASIMD_3(op) ((op & 0xee000e00) == 0xec000a00) // THUMB Extension register load/store instructions VFP
#define IS_THUMB_VFP_OR_ASIMD_4(op) ((op & 0xff100000) == 0xf9000000) // THUMB Advanced SIMD element or structure load/store instructions
#define IS_THUMB_VFP_OR_ASIMD_5(op) ((op & 0xef000e10) == 0xee000a10) // THUMB 8, 16, and 32-bit transfer between ARM core and extension registers
#define IS_THUMB_VFP_OR_ASIMD_6(op) ((op & 0xefe00e00) == 0xec400a00) // THUMB 64-bit transfers between ARM core and extension registers

#define IS_THUMB_VFP_OR_ASIMD(op)  ( \
	IS_THUMB_VFP_OR_ASIMD_1(op) ||   \
	IS_THUMB_VFP_OR_ASIMD_2(op) ||   \
	IS_THUMB_VFP_OR_ASIMD_3(op) ||   \
	IS_THUMB_VFP_OR_ASIMD_4(op) ||   \
	IS_THUMB_VFP_OR_ASIMD_5(op) ||   \
	IS_THUMB_VFP_OR_ASIMD_6(op))

#define IS_ARM_VFP_OR_ASIMD_1(op) ((op & 0x0f000e10) == 0x0e000a00) // ARM   Floating-point data-processing instructions
#define IS_ARM_VFP_OR_ASIMD_2(op) ((op & 0xfe000000) == 0xf2000000) // ARM   Advanced SIMD data-processing instructions
#define IS_ARM_VFP_OR_ASIMD_3(op) ((op & 0x0e000e00) == 0x0c000a00) // ARM   Extension register load/store instructions VFP
#define IS_ARM_VFP_OR_ASIMD_4(op) ((op & 0xff100000) == 0xf4000000) // ARM   Advanced SIMD element or structure load/store instructions
#define IS_ARM_VFP_OR_ASIMD_5(op) ((op & 0x0f000e10) == 0x0e000a10) // ARM   8, 16, and 32-bit transfer between ARM core and extension registers
#define IS_ARM_VFP_OR_ASIMD_6(op) ((op & 0x0fe00e00) == 0x0c400a00) // ARM   64-bit transfers between ARM core and extension registers

#define IS_ARM_VFP_OR_ASIMD(op)  ( \
	IS_ARM_VFP_OR_ASIMD_1(op) ||   \
	IS_ARM_VFP_OR_ASIMD_2(op) ||   \
	IS_ARM_VFP_OR_ASIMD_3(op) ||   \
	IS_ARM_VFP_OR_ASIMD_4(op) ||   \
	IS_ARM_VFP_OR_ASIMD_5(op) ||   \
	IS_ARM_VFP_OR_ASIMD_6(op))


namespace Disassembler {
	static const char *ARMRegisterToString(reg_t reg) {
		switch (reg) {
			default: return "INVALID_REGISTER";
			case r0: return "r0";
			case r1: return "r1";
			case r2: return "r2";
			case r3: return "r3";
			case r4: return "r4";
			case r5: return "r5";
			case r6: return "r6";
			case r7: return "r7";
			case r8: return "r8";
			case r9: return "r9";
			case r10: return "r10";
			case r11: return "r11";
			case r12: return "r12";
			case r13: return "r13";
			case r14: return "r14";
			case r15: return "r15";

			case cr0: return "cr0";
			case cr1: return "cr1";
			case cr2: return "cr2";
			case cr3: return "cr3";
			case cr4: return "cr4";
			case cr5: return "cr5";
			case cr6: return "cr6";
			case cr7: return "cr7";
			case cr8: return "cr8";
			case cr9: return "cr9";
			case cr10: return "cr10";
			case cr11: return "cr11";
			case cr12: return "cr12";
			case cr13: return "cr13";
			case cr14: return "cr14";
			case cr15: return "cr15";

			case d0: return "d0";
			case d1: return "d1";
			case d2: return "d2";
			case d3: return "d3";
			case d4: return "d4";
			case d5: return "d5";
			case d6: return "d6";
			case d7: return "d7";
			case d8: return "d8";
			case d9: return "d9";
			case d10: return "d10";
			case d11: return "d11";
			case d12: return "d12";
			case d13: return "d13";
			case d14: return "d14";
			case d15: return "d15";
			case d16: return "d16";
			case d17: return "d17";
			case d18: return "d18";
			case d19: return "d19";
			case d20: return "d20";
			case d21: return "d21";
			case d22: return "d22";
			case d23: return "d23";
			case d24: return "d24";
			case d25: return "d25";
			case d26: return "d26";
			case d27: return "d27";
			case d28: return "d28";
			case d29: return "d29";
			case d30: return "d30";
			case d31: return "d31";

			case s0: return "s0";
			case s1: return "s1";
			case s2: return "s2";
			case s3: return "s3";
			case s4: return "s4";
			case s5: return "s5";
			case s6: return "s6";
			case s7: return "s7";
			case s8: return "s8";
			case s9: return "s9";
			case s10: return "s10";
			case s11: return "s11";
			case s12: return "s12";
			case s13: return "s13";
			case s14: return "s14";
			case s15: return "s15";
			case s16: return "s16";
			case s17: return "s17";
			case s18: return "s18";
			case s19: return "s19";
			case s20: return "s20";
			case s21: return "s21";
			case s22: return "s22";
			case s23: return "s23";
			case s24: return "s24";
			case s25: return "s25";
			case s26: return "s26";
			case s27: return "s27";
			case s28: return "s28";
			case s29: return "s29";
			case s30: return "s30";
			case s31: return "s31";

			case q0: return "q0";
			case q1: return "q1";
			case q2: return "q2";
			case q3: return "q3";
			case q4: return "q4";
			case q5: return "q5";
			case q6: return "q6";
			case q7: return "q7";
			case q8: return "q8";
			case q9: return "q9";
			case q10: return "q10";
			case q11: return "q11";
			case q12: return "q12";
			case q13: return "q13";
			case q14: return "q14";
			case q15: return "q15";
		}
	}

	static const char *ARMCondCodeToString(cond_t CC) {
		switch (CC) {
			case COND_EQ:
				return "eq";
			case COND_NE:
				return "ne";
			case COND_HS:
				return "hs";
			case COND_LO:
				return "lo";
			case COND_MI:
				return "mi";
			case COND_PL:
				return "pl";
			case COND_VS:
				return "vs";
			case COND_VC:
				return "vc";
			case COND_HI:
				return "hi";
			case COND_LS:
				return "ls";
			case COND_GE:
				return "ge";
			case COND_LT:
				return "lt";
			case COND_GT:
				return "gt";
			case COND_LE:
				return "le";
			case COND_AL:
				return "al";
			case COND_UNCOND:
				return "";
			default:
				std::cerr << "Unknown condition code:" << (unsigned) CC << std::endl;
				assert(0 && "Unknown condition code");
				break;
		}

		return "INVALID";
	}

	static const char *ARMEncodingToString(ARMEncoding enc) {
		switch(enc) {
			case eEncodingT1: return "T1";
			case eEncodingT2: return "T2";
			case eEncodingT3: return "T3";
			case eEncodingT4: return "T4";
			case eEncodingT5: return "T5";
			case eEncodingA1: return "A1";
			case eEncodingA2: return "A2";
			case eEncodingA3: return "A3";
			case eEncodingA4: return "A4";
			case eEncodingA5: return "A5";
		}

		return "INVALID";
	}

	typedef enum ARMInstrSize {
		eSize16 = 16, eSize32 = 32
	} ARMInstrSize;

	class ARMInstruction {
		public:
			static ARMInstruction create() {
				return ARMInstruction {};
			}

			virtual ~ARMInstruction() {
			}

			// All the instructions share these fields.
			std::function<std::string(ARMInstruction *)> m_to_string;
			ARMEncoding encoding;
			unsigned opcode;
			unsigned id;
			ARMInstrSize ins_size;
			std::string m_decoded_by;
			bool m_skip;

			// Big union with all the fields of the different instructions.
			// ARMInstructionFields m_fields;

			// Maybe this should be a union.
			uint32_t imm12;
			uint32_t imm32;
			uint64_t imm64;

			virtual std::string toString() {
				return m_to_string ? m_to_string(this) : "invalid";
			}

			bool UnalignedAllowed;
			bool add;
			bool advsimd;
			bool dest_unsigned;
			bool double_to_single;
			bool dp_operation;
			bool floating_point;
			bool half_to_single;
			bool int_operation;
			bool is_pldw;
			bool is_tbh;
			bool is_vaddw;
			bool is_vsubw;
			bool is_vtbl;
			bool long_destination;
			bool m_high;
			bool m_swap;
			bool maximum;
			bool n_high;
			bool nonzero;
			bool op1_neg;
			bool or_equal;
			bool polynomial;
			bool postindex;
			bool quadword_operation;
			bool quiet_nan_exc;
			bool register_form;
			bool register_index;
			bool round;
			bool round_nearest;
			bool round_zero;
			bool scalar_form;
			bool set_bigend;
			bool setflags;
			bool single_reg;
			bool single_register;
			bool single_regs;
			bool src_unsigned;
			bool tbform;
			bool to_arm_register;
			bool to_arm_registers;
			bool to_fixed;
			bool to_integer;
			bool unsigned_;
			bool wback;
			bool with_zero;
			bool write_g;
			bool write_nzcvq;

			uint16_t ebytes;
			uint16_t elements;
			uint16_t esize;
			uint16_t esize_minus_one;
			uint16_t frac_bits;
			uint16_t groupsize;
			uint16_t groupsize_minus_one;
			uint16_t registers;

			uint8_t alignment;
			uint8_t carry;
			uint8_t cond;
			uint8_t cp;
			uint8_t ignored_0;
			uint8_t inc;
			uint8_t index;
			uint8_t length;
			uint8_t lowbit;
			uint8_t lsbit;
			uint8_t msbit;
			uint8_t operation;
			uint8_t position;
			uint8_t regs;
			uint8_t rotation;
			uint8_t saturate_to;
			uint8_t shift_amount;

			unsigned B;
			unsigned CRd;
			unsigned CRm;
			unsigned CRn;
			unsigned D;
			unsigned E;
			unsigned I1;
			unsigned I2;
			unsigned P;
			unsigned Q;
			unsigned SYSm;
			unsigned T;
			unsigned U;
			unsigned W;
			unsigned a;
			unsigned affectA;
			unsigned affectF;
			unsigned affectI;
			unsigned changemode;
			unsigned cmode;
			unsigned coproc;
			unsigned d2;
			unsigned d3;
			unsigned d4;
			unsigned d;
			unsigned dHi;
			unsigned dLo;
			unsigned disable;
			unsigned enable;
			unsigned firstcond;
			unsigned increment;
			unsigned m;
			unsigned mask;
			unsigned mode;
			unsigned n;
			unsigned op;
			unsigned opc1;
			unsigned opc2;
			unsigned opcode_;
			unsigned option;
			unsigned read_spsr;
			unsigned reg;
			unsigned reverse_mask;
			unsigned s;
			unsigned shift_n;
			unsigned shift_t;
			unsigned size;
			unsigned t2;
			unsigned t;
			unsigned targetInstrSet;
			unsigned type;
			unsigned widthminus1;
			unsigned wordhigher;
			unsigned write_spsr;
	};

	class UnpredictableInstruction: public ARMInstruction {
		private:
			std::string m_reason;

		public:
			UnpredictableInstruction(std::string reason) : m_reason(reason) {
				m_skip = false;
			}

			std::string toString() override {
				return "UnpredictableInstruction: " + m_reason;
			}
	};

	class UndefinedInstruction: public ARMInstruction {
		private:
			std::string m_reason;

		public:
			UndefinedInstruction(std::string reason) : m_reason(reason) {
				m_skip = false;
			}

			std::string toString() override {
				return "UndefinedInstruction: " + m_reason;
			}
	};

	class SeeInstruction: public ARMInstruction {
		public:
			SeeInstruction(const char *message) : m_see_message(message) {
				m_skip = true;
			}

			std::string toString() override {
				return m_see_message;
			}

		private:
			std::string m_see_message;
	};

	class UnknownInstruction: public ARMInstruction {
		public:
			std::string toString() override {
				return "UNKNOWN";
			}
	};

	class ARMDisassembler {
		public:
			ARMDisassembler(ARMVariants variant = ARMvAll);
			ARMInstruction disassemble(uint32_t opcode, ARMMode mode = ARMMode_ARM);

		private:
			ARMVariants m_variant;
			ARMDecoder *m_decoder;
	};
} /* namespace Disassembler */

#endif /* ARMDISASSEMBLER_H_ */
