/*
 * ThreadState.h
 *
 *  Created on: Jul 16, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_THREADSTATE_H_
#define SRC_LIBBINARY_MACHO_THREADSTATE_H_

#define x86_THREAD_STATE32		1
#define x86_FLOAT_STATE32		2
#define x86_EXCEPTION_STATE32	3
#define x86_THREAD_STATE64		4
#define x86_FLOAT_STATE64		5
#define x86_EXCEPTION_STATE64	6
#define x86_THREAD_STATE		7
#define x86_FLOAT_STATE			8
#define x86_EXCEPTION_STATE		9
#define x86_DEBUG_STATE32		10
#define x86_DEBUG_STATE64		11
#define x86_DEBUG_STATE			12
#define x86_THREAD_STATE_NONE	13
#define x86_SAVED_STATE_INT_1	14
#define x86_SAVED_STATE_INT_2	15
#define x86_AVX_STATE32			16
#define x86_AVX_STATE64			17
#define x86_AVX_STATE			18

#define ARM_THREAD_STATE		1
#define ARM_VFP_STATE			2
#define ARM_EXCEPTION_STATE		3
#define ARM_DEBUG_STATE			4
#define ARM_THREAD_STATE_NONE	5
#define ARM_THREAD_STATE64		6
#define ARM_EXCEPTION_STATE64	7
#define ARM_THREAD_STATE_LAST	8
#define ARM_SAVED_STATE32		(ARM_THREAD_STATE_LAST+1)
#define ARM_SAVED_STATE64		(ARM_THREAD_STATE_LAST+2)
#define ARM_NEON_SAVED_STATE32	(ARM_THREAD_STATE_LAST+3)
#define ARM_NEON_SAVED_STATE64	(ARM_THREAD_STATE_LAST+4)
#define ARM_VFP_STATE64			(ARM_THREAD_STATE_LAST+5)
#define ARM_DEBUG_STATE32		(ARM_THREAD_STATE_LAST+6)
#define ARM_DEBUG_STATE64		(ARM_THREAD_STATE_LAST+7)
#define ARM_NEON_STATE64		(ARM_THREAD_STATE_LAST+9)

struct thread_state_x86_32 {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t edi;
	uint32_t esi;
	uint32_t ebp;
	uint32_t esp;
	uint32_t ss;
	uint32_t eflags;
	uint32_t eip;
	uint32_t cs;
	uint32_t ds;
	uint32_t es;
	uint32_t fs;
	uint32_t gs;
};

struct thread_state_x86_64 {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rip;
	uint64_t rflags;
	uint64_t cs;
	uint64_t fs;
	uint64_t gs;
};

struct thread_state_arm_32 {
	uint32_t r[13];
	uint32_t sp;
	uint32_t lr;
	uint32_t pc;
	uint32_t cpsr;
	uint32_t far;
	uint32_t esr;
	uint32_t exception;
};

struct thread_state_arm_64 {
	uint64_t x[29];
	uint64_t fp;
	uint64_t lr;
	uint64_t sp;
	uint64_t pc;
	uint32_t cpsr;
	uint32_t reserved;
	uint64_t far;
	uint32_t esr;
	uint32_t exception;
};

struct arm_exception_state_32 {
	uint32_t exception;
	uint32_t fsr;
	uint32_t far;
};

struct arm_exception_state_64 {
	uint64_t exception;
	uint32_t fsr;
	uint32_t far;
};

struct arm_vfp_state {
	uint32_t r[64];
	uint32_t fpscr;
};

struct arm_debug_state_32 {
	uint32_t bvr[16];
	uint32_t bcr[16];
	uint32_t wvr[16];
	uint32_t wcr[16];
	uint64_t mdscr_el1;
};

struct arm_debug_state_64 {
	uint64_t bvr[16];
	uint64_t bcr[16];
	uint64_t wvr[16];
	uint64_t wcr[16];
	uint64_t mdscr_el1;
};

typedef struct {
	union {
		uint8_t as_uint8[16];
		uint16_t as_uint16[8];
		uint32_t as_uint32[4];
		uint64_t as_uint64[2];
	} value;
} uint128_t;

struct arm_neon_state_64 {
	uint128_t v[32];
	uint32_t fpsr;
	uint32_t fpcr;
};

struct arm_neon_state_32 {
	uint128_t v[16];
	uint32_t fpsr;
	uint32_t fpcr;
};

#endif /* SRC_LIBBINARY_MACHO_THREADSTATE_H_ */
