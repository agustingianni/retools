/*
 * ARMArch.h
 *
 *  Created on: Nov 1, 2015
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_ARM_ARMARCH_H_
#define SRC_LIBDISASSEMBLY_ARM_ARMARCH_H_

#include <cstdint>

typedef struct fpscr {
	unsigned IOC :1; 	// Invalid Operation cumulative flag
	unsigned DZC :1; 	// Division by Zero cumulative flag
	unsigned OFC :1; 	// Overflow cumulative flag
	unsigned UFC :1; 	// Underflow cumulative flag
	unsigned IXC :1; 	// Inexact cumulative flag
	unsigned DNM1 :2; 	// Do Not Modify
	unsigned IDC :1; 	// Input Subnormal cumulative flag
	unsigned IOE :1; 	// Invalid Operation exception enable bit
	unsigned DZE :1; 	// Division by Zero exception enable bit
	unsigned OFE :1; 	// Overflow exception enable bit
	unsigned UFE :1; 	// Underflow exception enable bit
	unsigned IXE :1; 	// Inexact exception enable bit
	unsigned DNM2 :2; 	// Do Not Modify
	unsigned IDE :1; 	// Input Subnormal exception enable bit
	unsigned LEN :3; 	//
	unsigned DNM3 :1;	// Do Not Modify
	unsigned STRIDE :2;	//
	unsigned RMODE :2; 	// Rounding mode control field
	unsigned FZ :1; // Flush-to-zero mode enable bit: 0 = flush-to-zero mode disabled 1 = flush-to-zero mode enabled.
	unsigned DN :1; // Default NaN mode enable bit: 0 = default NaN mode disabled 1 = default NaN mode enabled.
	unsigned DNM4 :1; 	// Do Not Modify
	unsigned QC :1; 	// Saturation cumulative flag
	unsigned V :1; 		// Set if comparison produces an unordered result
	unsigned C :1; // Set if comparison produces an equal, greater than, or unordered result
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
	VFPv1 = 1 << 14,
	VFPv2 = 1 << 15,
	VFPv3 = 1 << 16,
	VFPv4 = 1 << 17,
	AdvancedSIMD = 1 << 18,
	AdvancedSIMDv2 = 1 << 19,
	VFPAll = VFPv1 | VFPv2 | VFPv3 | VFPv4,
	AdvancedSIMDAll = AdvancedSIMD | AdvancedSIMDv2,
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

#endif /* SRC_LIBDISASSEMBLY_ARM_ARMARCH_H_ */
