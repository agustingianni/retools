#ifndef _MACH_MACHINE_H_
#define _MACH_MACHINE_H_

using cpu_type_t = int;
using cpu_subtype_t = int;
using cpu_threadtype_t = int;

#define CPU_STATE_MAX 4

#define CPU_STATE_USER 0
#define CPU_STATE_SYSTEM 1
#define CPU_STATE_IDLE 2
#define CPU_STATE_NICE 3

#define CPU_ARCH_MASK 0xff000000
#define CPU_ARCH_ABI64 0x01000000

#define CPU_TYPE_ANY ((cpu_type_t)-1)
#define CPU_TYPE_VAX ((cpu_type_t)1)
#define CPU_TYPE_MC680x0 ((cpu_type_t)6)
#define CPU_TYPE_X86 ((cpu_type_t)7)
#define CPU_TYPE_I386 CPU_TYPE_X86
#define CPU_TYPE_X86_64 (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_MC98000 ((cpu_type_t)10)
#define CPU_TYPE_HPPA ((cpu_type_t)11)
#define CPU_TYPE_ARM ((cpu_type_t)12)
#define CPU_TYPE_ARM64 (CPU_TYPE_ARM | CPU_ARCH_ABI64)
#define CPU_TYPE_MC88000 ((cpu_type_t)13)
#define CPU_TYPE_SPARC ((cpu_type_t)14)
#define CPU_TYPE_I860 ((cpu_type_t)15)
#define CPU_TYPE_POWERPC ((cpu_type_t)18)
#define CPU_TYPE_POWERPC64 (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)
#define CPU_SUBTYPE_MASK 0xff000000
#define CPU_SUBTYPE_LIB64 0x80000000
#define CPU_SUBTYPE_MULTIPLE ((cpu_subtype_t)-1)
#define CPU_SUBTYPE_LITTLE_ENDIAN ((cpu_subtype_t)0)
#define CPU_SUBTYPE_BIG_ENDIAN ((cpu_subtype_t)1)
#define CPU_THREADTYPE_NONE ((cpu_threadtype_t)0)
#define CPU_SUBTYPE_VAX_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_VAX780 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_VAX785 ((cpu_subtype_t)2)
#define CPU_SUBTYPE_VAX750 ((cpu_subtype_t)3)
#define CPU_SUBTYPE_VAX730 ((cpu_subtype_t)4)
#define CPU_SUBTYPE_UVAXI ((cpu_subtype_t)5)
#define CPU_SUBTYPE_UVAXII ((cpu_subtype_t)6)
#define CPU_SUBTYPE_VAX8200 ((cpu_subtype_t)7)
#define CPU_SUBTYPE_VAX8500 ((cpu_subtype_t)8)
#define CPU_SUBTYPE_VAX8600 ((cpu_subtype_t)9)
#define CPU_SUBTYPE_VAX8650 ((cpu_subtype_t)10)
#define CPU_SUBTYPE_VAX8800 ((cpu_subtype_t)11)
#define CPU_SUBTYPE_UVAXIII ((cpu_subtype_t)12)
#define CPU_SUBTYPE_MC680x0_ALL ((cpu_subtype_t)1)
#define CPU_SUBTYPE_MC68030 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_MC68040 ((cpu_subtype_t)2)
#define CPU_SUBTYPE_MC68030_ONLY ((cpu_subtype_t)3)
#define CPU_SUBTYPE_INTEL(f, m) ((cpu_subtype_t)(f) + ((m) << 4))
#define CPU_SUBTYPE_I386_ALL CPU_SUBTYPE_INTEL(3, 0)
#define CPU_SUBTYPE_386 CPU_SUBTYPE_INTEL(3, 0)
#define CPU_SUBTYPE_486 CPU_SUBTYPE_INTEL(4, 0)
#define CPU_SUBTYPE_486SX CPU_SUBTYPE_INTEL(4, 8)
#define CPU_SUBTYPE_586 CPU_SUBTYPE_INTEL(5, 0)
#define CPU_SUBTYPE_PENT CPU_SUBTYPE_INTEL(5, 0)
#define CPU_SUBTYPE_PENTPRO CPU_SUBTYPE_INTEL(6, 1)
#define CPU_SUBTYPE_PENTII_M3 CPU_SUBTYPE_INTEL(6, 3)
#define CPU_SUBTYPE_PENTII_M5 CPU_SUBTYPE_INTEL(6, 5)
#define CPU_SUBTYPE_CELERON CPU_SUBTYPE_INTEL(7, 6)
#define CPU_SUBTYPE_CELERON_MOBILE CPU_SUBTYPE_INTEL(7, 7)
#define CPU_SUBTYPE_PENTIUM_3 CPU_SUBTYPE_INTEL(8, 0)
#define CPU_SUBTYPE_PENTIUM_3_M CPU_SUBTYPE_INTEL(8, 1)
#define CPU_SUBTYPE_PENTIUM_3_XEON CPU_SUBTYPE_INTEL(8, 2)
#define CPU_SUBTYPE_PENTIUM_M CPU_SUBTYPE_INTEL(9, 0)
#define CPU_SUBTYPE_PENTIUM_4 CPU_SUBTYPE_INTEL(10, 0)
#define CPU_SUBTYPE_PENTIUM_4_M CPU_SUBTYPE_INTEL(10, 1)
#define CPU_SUBTYPE_ITANIUM CPU_SUBTYPE_INTEL(11, 0)
#define CPU_SUBTYPE_ITANIUM_2 CPU_SUBTYPE_INTEL(11, 1)
#define CPU_SUBTYPE_XEON CPU_SUBTYPE_INTEL(12, 0)
#define CPU_SUBTYPE_XEON_MP CPU_SUBTYPE_INTEL(12, 1)
#define CPU_SUBTYPE_INTEL_FAMILY(x) ((x)&15)
#define CPU_SUBTYPE_INTEL_FAMILY_MAX 15
#define CPU_SUBTYPE_INTEL_MODEL(x) ((x) >> 4)
#define CPU_SUBTYPE_INTEL_MODEL_ALL 0
#define CPU_SUBTYPE_X86_ALL ((cpu_subtype_t)3)
#define CPU_SUBTYPE_X86_64_ALL ((cpu_subtype_t)3)
#define CPU_SUBTYPE_X86_ARCH1 ((cpu_subtype_t)4)
#define CPU_SUBTYPE_X86_64_H ((cpu_subtype_t)8)
#define CPU_THREADTYPE_INTEL_HTT ((cpu_threadtype_t)1)
#define CPU_SUBTYPE_MIPS_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_MIPS_R2300 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_MIPS_R2600 ((cpu_subtype_t)2)
#define CPU_SUBTYPE_MIPS_R2800 ((cpu_subtype_t)3)
#define CPU_SUBTYPE_MIPS_R2000a ((cpu_subtype_t)4)
#define CPU_SUBTYPE_MIPS_R2000 ((cpu_subtype_t)5)
#define CPU_SUBTYPE_MIPS_R3000a ((cpu_subtype_t)6)
#define CPU_SUBTYPE_MIPS_R3000 ((cpu_subtype_t)7)
#define CPU_SUBTYPE_MC98000_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_MC98601 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_HPPA_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_HPPA_7100 ((cpu_subtype_t)0)
#define CPU_SUBTYPE_HPPA_7100LC ((cpu_subtype_t)1)
#define CPU_SUBTYPE_MC88000_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_MC88100 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_MC88110 ((cpu_subtype_t)2)
#define CPU_SUBTYPE_SPARC_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_I860_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_I860_860 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_POWERPC_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_POWERPC_601 ((cpu_subtype_t)1)
#define CPU_SUBTYPE_POWERPC_602 ((cpu_subtype_t)2)
#define CPU_SUBTYPE_POWERPC_603 ((cpu_subtype_t)3)
#define CPU_SUBTYPE_POWERPC_603e ((cpu_subtype_t)4)
#define CPU_SUBTYPE_POWERPC_603ev ((cpu_subtype_t)5)
#define CPU_SUBTYPE_POWERPC_604 ((cpu_subtype_t)6)
#define CPU_SUBTYPE_POWERPC_604e ((cpu_subtype_t)7)
#define CPU_SUBTYPE_POWERPC_620 ((cpu_subtype_t)8)
#define CPU_SUBTYPE_POWERPC_750 ((cpu_subtype_t)9)
#define CPU_SUBTYPE_POWERPC_7400 ((cpu_subtype_t)10)
#define CPU_SUBTYPE_POWERPC_7450 ((cpu_subtype_t)11)
#define CPU_SUBTYPE_POWERPC_970 ((cpu_subtype_t)100)
#define CPU_SUBTYPE_ARM_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_ARM_V4T ((cpu_subtype_t)5)
#define CPU_SUBTYPE_ARM_V6 ((cpu_subtype_t)6)
#define CPU_SUBTYPE_ARM_V5TEJ ((cpu_subtype_t)7)
#define CPU_SUBTYPE_ARM_XSCALE ((cpu_subtype_t)8)
#define CPU_SUBTYPE_ARM_V7 ((cpu_subtype_t)9)
#define CPU_SUBTYPE_ARM_V7F ((cpu_subtype_t)10)
#define CPU_SUBTYPE_ARM_V7S ((cpu_subtype_t)11)
#define CPU_SUBTYPE_ARM_V7K ((cpu_subtype_t)12)
#define CPU_SUBTYPE_ARM_V6M ((cpu_subtype_t)14)
#define CPU_SUBTYPE_ARM_V7M ((cpu_subtype_t)15)
#define CPU_SUBTYPE_ARM_V7EM ((cpu_subtype_t)16)
#define CPU_SUBTYPE_ARM_V8 ((cpu_subtype_t)13)
#define CPU_SUBTYPE_ARM64_ALL ((cpu_subtype_t)0)
#define CPU_SUBTYPE_ARM64_V8 ((cpu_subtype_t)1)
#define CPUFAMILY_UNKNOWN 0
#define CPUFAMILY_POWERPC_G3 0xcee41549
#define CPUFAMILY_POWERPC_G4 0x77c184ae
#define CPUFAMILY_POWERPC_G5 0xed76d8aa
#define CPUFAMILY_INTEL_6_13 0xaa33392b
#define CPUFAMILY_INTEL_YONAH 0x73d67300
#define CPUFAMILY_INTEL_MEROM 0x426f69ef
#define CPUFAMILY_INTEL_PENRYN 0x78ea4fbc
#define CPUFAMILY_INTEL_NEHALEM 0x6b5a4cd2
#define CPUFAMILY_INTEL_WESTMERE 0x573b5eec
#define CPUFAMILY_INTEL_SANDYBRIDGE 0x5490b78c
#define CPUFAMILY_INTEL_IVYBRIDGE 0x1f65e835
#define CPUFAMILY_INTEL_HASWELL 0x10b282dc
#define CPUFAMILY_INTEL_BROADWELL 0x582ed09c
#define CPUFAMILY_INTEL_SKYLAKE 0x37fc219f
#define CPUFAMILY_ARM_9 0xe73283ae
#define CPUFAMILY_ARM_11 0x8ff620d8
#define CPUFAMILY_ARM_XSCALE 0x53b005f5
#define CPUFAMILY_ARM_12 0xbd1b0ae9
#define CPUFAMILY_ARM_13 0x0cc90e64
#define CPUFAMILY_ARM_14 0x96077ef1
#define CPUFAMILY_ARM_15 0xa8511bca
#define CPUFAMILY_ARM_SWIFT 0x1e2d6381
#define CPUFAMILY_ARM_CYCLONE 0x37a09642
#define CPUFAMILY_ARM_TYPHOON 0x2c91a47e
#define CPUFAMILY_ARM_TWISTER 0x92fb37c8
#define CPUFAMILY_INTEL_6_14 CPUFAMILY_INTEL_YONAH
#define CPUFAMILY_INTEL_6_15 CPUFAMILY_INTEL_MEROM
#define CPUFAMILY_INTEL_6_23 CPUFAMILY_INTEL_PENRYN
#define CPUFAMILY_INTEL_6_26 CPUFAMILY_INTEL_NEHALEM
#define CPUFAMILY_INTEL_CORE CPUFAMILY_INTEL_YONAH
#define CPUFAMILY_INTEL_CORE2 CPUFAMILY_INTEL_MEROM

#endif
