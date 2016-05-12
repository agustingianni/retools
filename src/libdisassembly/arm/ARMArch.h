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

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} fpscr_t;

typedef struct apsr {
    unsigned DNM1 :16;  // Do not modify.
    unsigned GE :4;     // The Greater than or Equal flags.
    unsigned DNM2 :4;   // Do not modify.
    unsigned RAZ :3;    // ?
    unsigned Q :1;      // Set to 1 to indicate overflow or saturation.
    unsigned V :1;      // Overflow condition flag.
    unsigned C :1;      // Carry condition flag.
    unsigned Z :1;      // Zero condition flag.
    unsigned N :1;      // Negative condition flag.

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} apsr_t;

typedef struct hstr {
    unsigned UNK :14;
    unsigned TJDBX :1;
    unsigned TTEE :1;
    unsigned T15 :1;
    unsigned T14 :1;
    unsigned T13 :1;
    unsigned T12 :1;
    unsigned T11 :1;
    unsigned T10 :1;
    unsigned T9 :1;
    unsigned T8 :1;
    unsigned T7 :1;
    unsigned T6 :1;
    unsigned T5 :1;
    unsigned T4 :1;
    unsigned T3 :1;
    unsigned T2 :1;
    unsigned T1 :1;
    unsigned T0 :1;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} hstr_t;

typedef struct jmcr {
    unsigned UNK :31;
    unsigned JE :1;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} jmcr_t;

typedef struct hcr {
    unsigned UNK :4;
    unsigned TGE :1;
    unsigned TVM :1;
    unsigned TTLB :1;
    unsigned TPU :1;
    unsigned TPC :1;
    unsigned TSW :1;
    unsigned TAC :1;
    unsigned TIDCP :1;
    unsigned TSC :1;
    unsigned TID3 :1;
    unsigned TID2 :1;
    unsigned TID1 :1;
    unsigned TID0 :1;
    unsigned TWE :1;
    unsigned TWI :1;
    unsigned MISSING_NAME :1;
    unsigned BSU :2;
    unsigned FB :1;
    unsigned VA :1;
    unsigned VI :1;
    unsigned VF :1;
    unsigned AMO :1;
    unsigned IMO :1;
    unsigned FMO :1;
    unsigned PTW :1;
    unsigned SWIO :1;
    unsigned VM :1;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} hcr_t;

typedef struct cpsr {
    unsigned N: 1;
    unsigned Z: 1;
    unsigned C: 1;
    unsigned V: 1;
    unsigned Q: 1;
    unsigned IT_1_0: 2;
    unsigned J: 1;
    unsigned RAZ: 4;
    unsigned GE: 4;
    unsigned IT_7_2: 6;
    unsigned E: 1;
    unsigned A: 1;
    unsigned I: 1;
    unsigned F: 1;
    unsigned T: 1;
    unsigned M: 5;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} cpsr_t;

typedef cpsr_t spsr_t;

typedef struct scr {
    unsigned UNK: 22;
    unsigned SIF: 1;
    unsigned HCE: 1;
    unsigned SCD: 1;
    unsigned nET: 1;
    unsigned AW: 1;
    unsigned FW: 1;
    unsigned EA: 1;
    unsigned FIQ: 1;
    unsigned IRQ: 1;
    unsigned NS: 1;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} scr_t;

typedef struct itstate {
    unsigned char IT;
} itstate_t;

typedef struct nsacr {
    unsigned UNK: 11;
    unsigned NSTRCDIS: 1;
    unsigned RFR: 1;
    unsigned IMPLEMENTATION_DEFINED: 3;
    unsigned NSASEDIS: 1;
    unsigned NSD32DIS: 1;
    unsigned cp13: 1;
    unsigned cp12: 1;
    unsigned cp11: 1;
    unsigned cp10: 1;
    unsigned cp9: 1;
    unsigned cp8: 1;
    unsigned cp7: 1;
    unsigned cp6: 1;
    unsigned cp5: 1;
    unsigned cp4: 1;
    unsigned cp3: 1;
    unsigned cp2: 1;
    unsigned cp1: 1;
    unsigned cp0: 1;

    operator unsigned() const {
        return *reinterpret_cast<const unsigned *>(this);
    }

    void operator=(unsigned value) {
        *reinterpret_cast<unsigned *>(this) = value;
    }

} nsacr_t;

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

namespace Register {
enum Core {
    ARM_REG_R0 = 0,
    ARM_REG_R1,
    ARM_REG_R2,
    ARM_REG_R3,
    ARM_REG_R4,
    ARM_REG_R5,
    ARM_REG_R6,
    ARM_REG_R7,
    ARM_REG_R8,
    ARM_REG_R9,
    ARM_REG_R10,
    ARM_REG_R11,
    ARM_REG_R12,
    ARM_REG_R13,
    ARM_REG_R14,
    ARM_REG_R15,
    ARM_REG_CORE_MAX,
    ARM_REG_SB = ARM_REG_R9,
    ARM_REG_SL = ARM_REG_R10,
    ARM_REG_FP = ARM_REG_R11,
    ARM_REG_IP = ARM_REG_R12,
    ARM_REG_SP = ARM_REG_R13,
    ARM_REG_LR = ARM_REG_R14,
    ARM_REG_PC = ARM_REG_R15
};

enum Coproc {
    ARM_REG_CR0 = 0,
    ARM_REG_CR1,
    ARM_REG_CR2,
    ARM_REG_CR3,
    ARM_REG_CR4,
    ARM_REG_CR5,
    ARM_REG_CR6,
    ARM_REG_CR7,
    ARM_REG_CR8,
    ARM_REG_CR9,
    ARM_REG_CR10,
    ARM_REG_CR11,
    ARM_REG_CR12,
    ARM_REG_CR13,
    ARM_REG_CR14,
    ARM_REG_CR15,
    ARM_REG_COPROC_MAX
};

enum Single {
    ARM_REG_S0 = 0,
    ARM_REG_S1,
    ARM_REG_S2,
    ARM_REG_S3,
    ARM_REG_S4,
    ARM_REG_S5,
    ARM_REG_S6,
    ARM_REG_S7,
    ARM_REG_S8,
    ARM_REG_S9,
    ARM_REG_S10,
    ARM_REG_S11,
    ARM_REG_S12,
    ARM_REG_S13,
    ARM_REG_S14,
    ARM_REG_S15,
    ARM_REG_S16,
    ARM_REG_S17,
    ARM_REG_S18,
    ARM_REG_S19,
    ARM_REG_S20,
    ARM_REG_S21,
    ARM_REG_S22,
    ARM_REG_S23,
    ARM_REG_S24,
    ARM_REG_S25,
    ARM_REG_S26,
    ARM_REG_S27,
    ARM_REG_S28,
    ARM_REG_S29,
    ARM_REG_S30,
    ARM_REG_S31,
    ARM_REG_SINGLE_MAX
};

enum Double {
    ARM_REG_D0 = 0,
    ARM_REG_D1,
    ARM_REG_D2,
    ARM_REG_D3,
    ARM_REG_D4,
    ARM_REG_D5,
    ARM_REG_D6,
    ARM_REG_D7,
    ARM_REG_D8,
    ARM_REG_D9,
    ARM_REG_D10,
    ARM_REG_D11,
    ARM_REG_D12,
    ARM_REG_D13,
    ARM_REG_D14,
    ARM_REG_D15,
    ARM_REG_D16,
    ARM_REG_D17,
    ARM_REG_D18,
    ARM_REG_D19,
    ARM_REG_D20,
    ARM_REG_D21,
    ARM_REG_D22,
    ARM_REG_D23,
    ARM_REG_D24,
    ARM_REG_D25,
    ARM_REG_D26,
    ARM_REG_D27,
    ARM_REG_D28,
    ARM_REG_D29,
    ARM_REG_D30,
    ARM_REG_D31,
    ARM_REG_DOUBLE_MAX
};

enum Quad {
    ARM_REG_Q0 = 0,
    ARM_REG_Q1,
    ARM_REG_Q2,
    ARM_REG_Q3,
    ARM_REG_Q4,
    ARM_REG_Q5,
    ARM_REG_Q6,
    ARM_REG_Q7,
    ARM_REG_Q8,
    ARM_REG_Q9,
    ARM_REG_Q10,
    ARM_REG_Q11,
    ARM_REG_Q12,
    ARM_REG_Q13,
    ARM_REG_Q14,
    ARM_REG_Q15,
    ARM_REG_QUAD_MAX
};
}

// XXX: Remove this.
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

typedef enum MBReqDomain {
    MBReqDomain_FullSystem,
    MBReqDomain_OuterShareable,
    MBReqDomain_InnerShareable,
    MBReqDomain_Nonshareable
} MBReqDomain;

typedef enum MBReqTypes {
    MBReqTypes_All,
    MBReqTypes_Writes
} MBReqTypes;

typedef enum FPType {
    FPType_Nonzero,
    FPType_Zero,
    FPType_Infinity,
    FPType_QNaN,
    FPType_SNaN
} FPType;

typedef enum FPExc {
    FPExc_InvalidOp,
    FPExc_DivideByZero,
    FPExc_Overflow,
    FPExc_Underflow,
    FPExc_Inexact,
    FPExc_InputDenorm
} FPExc;

typedef enum RName {
    RName_0usr,
    RName_1usr,
    RName_2usr,
    RName_3usr,
    RName_4usr,
    RName_5usr,
    RName_6usr,
    RName_7usr,
    RName_8usr,
    RName_8fiq,
    RName_9usr,
    RName_9fiq,
    RName_10usr,
    RName_10fiq,
    RName_11usr,
    RName_11fiq,
    RName_12usr,
    RName_12fiq,
    RName_SPusr,
    RName_SPfiq,
    RName_SPirq,
    RName_SPsvc,
    RName_SPabt,
    RName_SPund,
    RName_SPmon,
    RName_SPhyp,
    RName_LRusr,
    RName_LRfiq,
    RName_LRirq,
    RName_LRsvc,
    RName_LRabt,
    RName_LRund,
    RName_LRmon,
    RName_PC
} RName;

typedef enum MemType {
    MemType_Normal,
    MemType_Device,
    MemType_StronglyOrdered
} MemType;

typedef enum DAbort {
    DAbort_AccessFlag,
    DAbort_Alignment,
    DAbort_Background,
    DAbort_Domain,
    DAbort_Permission,
    DAbort_Translation,
    DAbort_SyncExternal,
    DAbort_SyncExternalonWalk,
    DAbort_SyncParity,
    DAbort_SyncParityonWalk,
    DAbort_AsyncParity,
    DAbort_AsyncExternal,
    DAbort_DebugEvent,
    DAbort_TLBConflict,
    DAbort_Lockdown,
    DAbort_Coproc,
    DAbort_ICacheMaint
} DAbort;

typedef enum TLBRecType {
    TLBRecType_SmallPage,
    TLBRecType_LargePage,
    TLBRecType_Section,
    TLBRecType_Supersection,
    TLBRecType_MMUDisabled
} TLBRecType;

typedef enum UndefinedValue {
	UNKNOWN_VALUE
} UndefinedValue;

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
