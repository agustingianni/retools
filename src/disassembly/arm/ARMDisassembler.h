/*
 * ARMDisassembler.h
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#ifndef ARMDISASSEMBLER_H_
#define ARMDISASSEMBLER_H_

#include <vector>
#include <deque>
#include <functional>
#include <cassert>
#include <string>
#include <iostream>

class ARMDecoder;

namespace Disassembler {
	typedef struct fpscr {
			unsigned IOC :1; 	// Invalid Operation cumulative flag
			unsigned DZC :1; 	// Division by Zero cumulative flag
			unsigned OFC :1; 	// Overflow cumulative flag
			unsigned UFC :1; 	// Underflow cumulative flag
			unsigned IXC :1; 	// Inexact cumulative flag
			unsigned DNM1:2; 	// Do Not Modify
			unsigned IDC :1; 	// Input Subnormal cumulative flag
			unsigned IOE :1; 	// Invalid Operation exception enable bit
			unsigned DZE :1; 	// Division by Zero exception enable bit
			unsigned OFE :1; 	// Overflow exception enable bit
			unsigned UFE :1; 	// Underflow exception enable bit
			unsigned IXE :1; 	// Inexact exception enable bit
			unsigned DNM2:2; 	// Do Not Modify
			unsigned IDE :1; 	// Input Subnormal exception enable bit
			unsigned LEN :3; 	//
			unsigned DNM3:1;	// Do Not Modify
			unsigned STRIDE :2;	//
			unsigned RMODE :2; 	// Rounding mode control field
			unsigned FZ :1; 	// Flush-to-zero mode enable bit: 0 = flush-to-zero mode disabled 1 = flush-to-zero mode enabled.
			unsigned DN :1; 	// Default NaN mode enable bit: 0 = default NaN mode disabled 1 = default NaN mode enabled.
			unsigned DNM4:1; 	// Do Not Modify
			unsigned QC :1; 	// Saturation cumulative flag
			unsigned V :1; 		// Set if comparison produces an unordered result
			unsigned C :1; 		// Set if comparison produces an equal, greater than, or unordered result
			unsigned Z :1; 		// Set if comparison produces an equal result
			unsigned N :1; 		// Set if comparison produces a less than result
	} fpscr_t;

	typedef struct apsr {
			unsigned DNM1 :16;	// Do not modify.
			unsigned GE :4;		// The Greater than or Equal flags.
			unsigned DNM2 :4;	// Do not modify.
			unsigned RAZ :3;	// ?
			unsigned Q :1;		// Set to 1 to indicate overflow or saturation.
			unsigned V :1;		// Overflow condition flag.
			unsigned C :1;		// Carry condition flag.
			unsigned Z :1;		// Zero condition flag.
			unsigned N :1;		// Negative condition flag.
	} apsr_t;

	// enumeration VCGTtype {VCGTtype_signed, VCGTtype_unsigned, VCGTtype_fp};
	typedef enum VCGTtype {
		VCGTtype_signed, VCGTtype_unsigned, VCGTtype_fp
	} VCGTtype;

	typedef enum VCGEtype {
		VCGEtype_signed, VCGEtype_unsigned, VCGEtype_fp
	} VCGEtype;

	typedef enum VFPNegMul {
		VFPNegMul_VNMLA, VFPNegMul_VNMLS, VFPNegMul_VNMUL
	} VFPNegMul;

	typedef enum VBitOps {
		VBitOps_VBIF, VBitOps_VBIT, VBitOps_VBSL
	} VBitOps;

	typedef enum ARMMode {
		ARMMode_ARM,
		ARMMode_Thumb,
		ARMMode_Jazelle,
		ARMMode_ThumbEE,
		ARMMode_Invalid,
		InstrSet_ARM = ARMMode_ARM,
		InstrSet_Thumb = ARMMode_Thumb,
		InstrSet_Jazelle = ARMMode_Jazelle,
		InstrSet_ThumbEE = ARMMode_ThumbEE
	} ARMMode;

	typedef enum shift_t {
		SRType_LSL, SRType_LSR, SRType_ASR, SRType_ROR, SRType_RRX, SRType_Invalid
	} shift_t;

	typedef enum reg_t {
		// Core registers.
		r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11,
		r12, r13, r14, r15,

		// Coprocessor registers.
		cr0, cr1, cr2, cr3, cr4, cr5, cr6, cr7, cr8, cr9,
		cr10, cr11, cr12, cr13, cr14, cr15,

		// Advanced SIMD double-word registers (64bits).
		d0, d1, d2, d3, d4, d5, d6, d7, d8, d9,
		d10, d11, d12, d13, d14, d15, d16, d17,
		d18, d19, d20, d21, d22, d23, d24, d25,
		d26, d27, d28, d29, d30, d31,

		s0, s1, s2, s3, s4, s5, s6, s7, s8,
		s9, s10, s11, s12, s13, s14, s15,
		s16, s17, s18, s19, s20, s21, s22,
		s23, s24, s25, s26, s27, s28, s29,
		s30, s31,

		// Advanced SIMD quad-word registers (128bits).
		q0, q1, q2, q3, q4, q5, q6, q7, q8,
		q9, q10, q11, q12, q13, q14, q15,
	} reg_t;

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

	typedef enum cond_t {
		COND_EQ = 0,
		COND_NE = 1,
		COND_CS = 2,
		COND_CC = 3,
		COND_MI = 4,
		COND_PL = 5,
		COND_VS = 6,
		COND_VC = 7,
		COND_HI = 8,
		COND_LS = 9,
		COND_GE = 10,
		COND_LT = 11,
		COND_GT = 12,
		COND_LE = 13,
		COND_AL = 14,

		COND_HS = COND_CS,
		COND_LO = COND_CC,
		COND_UNCOND = 15,
	} cond_t;

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
				return "UNCOND";
			default:
				std::cerr << "Unknown condition code:" << (unsigned) CC << std::endl;
				assert(0 && "Unknown condition code");
				break;
		}

		return "INVALID";
	}

	typedef enum option_t {
		O_OSHST = 2,
		O_OSH = 3,
		O_NSHST = 6,
		O_NSH = 7,
		O_ISHST = 10,
		O_ISH = 11,
		O_ST = 14,
		O_SY = 15,

		O_OPTIONCNT,
		O_INVLD = -1,
		O_BASE = 0,
	} option_t;

	typedef enum coproc_t {
		p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15,

		P_PROCCNT, P_INVLD = -1, P_BASE = p0,
	} coproc_t;

	typedef enum ARMVariants {
		ARMv4 = 1 << 0,
		ARMv4T = 1 << 1,
		ARMv4All = ARMv4 | ARMv4T,	// ARMv4*

		ARMv5T = 1 << 2,
		ARMv5TE = 1 << 3,
		ARMv5TEJ = 1 << 4,
		ARMv5TEAll = ARMv5TE | ARMv5TEJ, // ARMv5TE*
		ARMv5TAll = ARMv5T | ARMv5TE | ARMv5TEJ, // ARMv5T*

		ARMv6 = 1 << 5,
		ARMv6K = 1 << 6,
		ARMv6T2 = 1 << 7,
		ARMv6All = ARMv6 | ARMv6K | ARMv6T2, // ARMv6*

		ARMv7 = 1 << 8,
		ARMv7S = 1 << 9,
		ARMv7VE = 1 << 10,
		ARMv7R = 1 << 11,
		ARMv7All = ARMv7 | ARMv7S | ARMv7S | ARMv7VE | ARMv7R, // ARMv7*

		ARMv8 = 1 << 12,
		ARMSecurityExtension = 1 << 13,
		ARMvAll = 0xffffffff,
	} ARMVariants;

	typedef enum ARMVFPVersion {
		No_VFP = 0,
		VFPv1 = (1u << 1),
		VFPv2 = (1u << 2),
		VFPv3 = (1u << 3),
		VFPv4 = (1u << 4),
		AdvancedSIMD = (1u << 5),
		AdvancedSIMDv2 = (1u << 6),
		VFPv1_ABOVE = (VFPv1 | VFPv2 | VFPv3 | AdvancedSIMD),
		VFPv2_ABOVE = (VFPv2 | VFPv3 | AdvancedSIMD),
		VFPv2v3 = (VFPv2 | VFPv3)
	} ARMVFPVersion;

	typedef enum ARMEncoding {
		eEncodingA1,
		eEncodingA2,
		eEncodingA3,
		eEncodingA4,
		eEncodingA5,
		eEncodingT1,
		eEncodingT2,
		eEncodingT3,
		eEncodingT4,
		eEncodingT5
	} ARMEncoding;

	typedef enum ARMInstrSize {
		eSize16, eSize32
	} ARMInstrSize;

	class ARMInstruction {
		public:
			static std::shared_ptr<ARMInstruction> create() {
				std::shared_ptr<ARMInstruction> ins;
				// memset(reinterpret_cast<void *>(&ins), 0, sizeof(ARMInstruction));
				return ins;
			}

			virtual ~ARMInstruction() {
			}

			std::function<std::string(ARMInstruction *)> m_to_string;

			virtual std::string toString() {
				return m_to_string ? m_to_string(this) : "to_string_missing";
			}

			ARMInstrSize ins_size;

			bool m_skip;

			unsigned read_spsr;
			unsigned write_spsr;
			unsigned changemode;
			unsigned enable;
			unsigned disable;
			unsigned affectI;
			unsigned affectA;
			unsigned affectF;
			unsigned SYSm;

			unsigned increment;
			unsigned wordhigher;

			unsigned id;
			unsigned U;
			unsigned P;
			unsigned D;
			unsigned W;
			unsigned op;
			unsigned imm3;
			unsigned imm6;

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

			unsigned B;
			uint16_t ebytes;
			uint16_t elements;
			uint16_t esize;
			uint16_t esize_minus_one;
			uint16_t frac_bits;
			uint16_t groupsize;
			uint16_t groupsize_minus_one;
			uint16_t imm5;
			uint16_t imm16;
			uint16_t registers;
			uint32_t imm32;
			uint64_t imm64;
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

			unsigned coproc;
			unsigned opc1;
			unsigned CRd;
			unsigned CRn;
			unsigned CRm;
			unsigned opc2;
			unsigned option;

			unsigned I1;
			unsigned I2;

			unsigned d2;
			unsigned d3;
			unsigned d4;
			unsigned a;
			unsigned d;
			unsigned m;
			unsigned n;
			unsigned s;
			unsigned t;
			unsigned t2;
			unsigned dHi;
			unsigned dLo;

			unsigned encoding;
			unsigned opcode;

			unsigned reverse_mask;

			unsigned shift_n;
			unsigned shift_t;

			unsigned size;
			unsigned targetInstrSet;
			unsigned type;
			unsigned widthminus1;
	};

	class UnpredictableInstruction: public ARMInstruction {
		public:
			std::string toString() override {
				return "UnpredictableInstruction";
			}
	};

	class UndefinedInstruction: public ARMInstruction {
		public:
			std::string toString() override {
				return "UndefinedInstruction";
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
			ARMDisassembler(ARMVariants variant = ARMv7);
			std::shared_ptr<ARMInstruction> disassemble(uint32_t opcode, ARMMode mode = ARMMode_ARM);

		private:
			ARMVariants m_variant;
			ARMDecoder *m_decoder;
	};

	class ITSession {
	    public:
	        ITSession() :
	                ITCounter(0), ITState(0) {
	        }

	        ~ITSession() {
	        }

	        bool InitIT(uint32_t bits7_0);
	        void ITAdvance();
	        bool InITBlock();
	        bool LastInITBlock();
	        uint32_t GetCond();

	    private:
	        uint32_t ITCounter;
	        uint32_t ITState;
	};
} /* namespace Disassembler */

#endif /* ARMDISASSEMBLER_H_ */
