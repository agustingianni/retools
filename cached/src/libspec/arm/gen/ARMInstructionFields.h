union ARMInstructionFields {
    struct adc_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct adc_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct adc_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct add_immediate_arm {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct add_immediate_thumb {
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct add_register_arm {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct add_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct add_register_thumb {
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct add_sp_plus_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned setflags;
    };

    struct add_sp_plus_register_arm {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct add_sp_plus_register_thumb {
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct adr {
        unsigned add;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
    };

    struct and_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct and_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct and_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct asr_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
    };

    struct asr_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct b {
        unsigned I1;
        unsigned I2;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
    };

    struct bfc {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned lsbit;
        unsigned msbit;
    };

    struct bfi {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned lsbit;
        unsigned msbit;
        unsigned n;
    };

    struct bic_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct bic_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct bic_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct bkpt {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
    };

    struct bl_blx_immediate {
        unsigned I1;
        unsigned I2;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned targetInstrSet;
    };

    struct blx_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
    };

    struct bx {
        unsigned cond;
        unsigned encoding;
        unsigned m;
    };

    struct bxj {
        unsigned cond;
        unsigned encoding;
        unsigned m;
    };

    struct cbnz_cbz {
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned nonzero;
        unsigned op;
    };

    struct cdp_cdp2 {
        unsigned CRd;
        unsigned CRm;
        unsigned CRn;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned opc1;
        unsigned opc2;
    };

    struct clrex {
        unsigned encoding;
    };

    struct clz {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
    };

    struct cmn_immediate {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
    };

    struct cmn_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct cmn_register_shifted_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned shift_t;
        unsigned type;
    };

    struct cmp_immediate {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
    };

    struct cmp_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct cmp_register_shifted_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned shift_t;
        unsigned type;
    };

    struct cps_arm {
        unsigned affectA;
        unsigned affectF;
        unsigned affectI;
        unsigned changemode;
        unsigned disable;
        unsigned enable;
        unsigned encoding;
        unsigned mode;
    };

    struct cps_thumb {
        unsigned affectA;
        unsigned affectF;
        unsigned affectI;
        unsigned changemode;
        unsigned disable;
        unsigned enable;
        unsigned encoding;
        unsigned mode;
    };

    struct dbg {
        unsigned cond;
        unsigned encoding;
        unsigned option;
    };

    struct dmb {
        unsigned encoding;
        unsigned option;
    };

    struct dsb {
        unsigned encoding;
        unsigned option;
    };

    struct eor_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct eor_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct eor_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct eret {
        unsigned cond;
        unsigned encoding;
    };

    struct hvc {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
    };

    struct isb {
        unsigned encoding;
        unsigned option;
    };

    struct it {
        unsigned encoding;
        unsigned firstcond;
        unsigned mask;
    };

    struct ldc_ldc2_immediate {
        unsigned CRd;
        unsigned D;
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned wback;
    };

    struct ldc_ldc2_literal {
        unsigned CRd;
        unsigned D;
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
    };

    struct ldm_exception_return {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned increment;
        unsigned n;
        unsigned registers;
        unsigned wback;
        unsigned wordhigher;
    };

    struct ldm_ldmia_ldmfd_arm {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct ldm_ldmia_ldmfd_thumb {
        unsigned P;
        unsigned W;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct ldm_user_registers {
        unsigned P;
        unsigned U;
        unsigned cond;
        unsigned encoding;
        unsigned increment;
        unsigned n;
        unsigned registers;
        unsigned wordhigher;
    };

    struct ldmda_ldmfa {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct ldmdb_ldmea {
        unsigned P;
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct ldmib_ldmed {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct ldr_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldr_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldr_literal {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
    };

    struct ldr_register_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
        unsigned wback;
    };

    struct ldr_register_thumb {
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
    };

    struct ldrb_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrb_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrb_literal {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
    };

    struct ldrb_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
        unsigned wback;
    };

    struct ldrbt {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
    };

    struct ldrd_immediate {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned t2;
        unsigned wback;
    };

    struct ldrd_literal {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
        unsigned t2;
    };

    struct ldrd_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned t;
        unsigned t2;
        unsigned wback;
    };

    struct ldrex {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned t;
    };

    struct ldrexb {
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned t;
    };

    struct ldrexd {
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned t;
        unsigned t2;
    };

    struct ldrexh {
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned t;
    };

    struct ldrh_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrh_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrh_literal {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
    };

    struct ldrh_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned wback;
    };

    struct ldrht {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned t;
    };

    struct ldrsb_immediate {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrsb_literal {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
    };

    struct ldrsb_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned wback;
    };

    struct ldrsbt {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned t;
    };

    struct ldrsh_immediate {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct ldrsh_literal {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned t;
    };

    struct ldrsh_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned wback;
    };

    struct ldrsht {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned t;
    };

    struct ldrt {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
    };

    struct lsl_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
    };

    struct lsl_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct lsr_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
    };

    struct lsr_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct mcr_mcr2 {
        unsigned CRm;
        unsigned CRn;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned opc1;
        unsigned opc2;
        unsigned t;
    };

    struct mcrr_mcrr2 {
        unsigned CRm;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned opc1;
        unsigned t;
        unsigned t2;
    };

    struct mla {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct mls {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct mov_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned setflags;
    };

    struct mov_register_arm {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
    };

    struct mov_register_thumb {
        unsigned D;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
    };

    struct movt {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
    };

    struct mrc_mrc2 {
        unsigned CRm;
        unsigned CRn;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned opc1;
        unsigned opc2;
        unsigned t;
    };

    struct mrrc_mrrc2 {
        unsigned CRm;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned opc1;
        unsigned t;
        unsigned t2;
    };

    struct mrs {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned read_spsr;
    };

    struct mrs_banked_register {
        unsigned SYSm;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned read_spsr;
    };

    struct msr_immediate {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned mask;
        unsigned write_g;
        unsigned write_nzcvq;
    };

    struct msr_register {
        unsigned cond;
        unsigned encoding;
        unsigned mask;
        unsigned n;
        unsigned write_spsr;
    };

    struct mul {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct mvn_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned setflags;
    };

    struct mvn_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct mvn_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct nop {
        unsigned cond;
        unsigned encoding;
    };

    struct orn_immediate {
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct orn_register {
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct orr_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct orr_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct orr_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct pkh {
        unsigned T;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned tbform;
    };

    struct pld_literal {
        unsigned U;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
    };

    struct pld_pldw_immediate {
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned is_pldw;
        unsigned n;
    };

    struct pld_pldw_register {
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned is_pldw;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct pli_immediate_literal {
        unsigned U;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
    };

    struct pli_register {
        unsigned U;
        unsigned add;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct pop_arm {
        unsigned UnalignedAllowed;
        unsigned cond;
        unsigned encoding;
        unsigned registers;
        unsigned t;
    };

    struct pop_thumb {
        unsigned P;
        unsigned UnalignedAllowed;
        unsigned encoding;
        unsigned registers;
        unsigned t;
    };

    struct push {
        unsigned UnalignedAllowed;
        unsigned cond;
        unsigned encoding;
        unsigned registers;
        unsigned t;
    };

    struct qadd {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qdadd {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qdsub {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qsax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qsub {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qsub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct qsub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct rbit {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
    };

    struct rev {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
    };

    struct rev16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
    };

    struct revsh {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
    };

    struct rfe {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned encoding;
        unsigned inc;
        unsigned increment;
        unsigned n;
        unsigned wback;
        unsigned wordhigher;
    };

    struct ror_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
    };

    struct ror_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct rrx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
    };

    struct rsb_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct rsb_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct rsb_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct rsc_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct rsc_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct rsc_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct sadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct sadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct sasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct sbc_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct sbc_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct sbc_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct sbfx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned lsbit;
        unsigned n;
        unsigned widthminus1;
    };

    struct sdiv {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct sel {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct setend {
        unsigned E;
        unsigned encoding;
        unsigned set_bigend;
    };

    struct sev {
        unsigned cond;
        unsigned encoding;
    };

    struct shadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct shadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct shasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct shsax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct shsub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct shsub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct smc_previously_smi {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
    };

    struct smlabb_smlabt_smlatb_smlatt {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_high;
        unsigned n;
        unsigned n_high;
    };

    struct smlad {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct smlal {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct smlalbb_smlalbt_smlaltb_smlaltt {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned m_high;
        unsigned n;
        unsigned n_high;
    };

    struct smlald {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct smlawb_smlawt {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_high;
        unsigned n;
    };

    struct smlsd {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct smlsld {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct smmla {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned round;
    };

    struct smmls {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned round;
    };

    struct smmul {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned round;
    };

    struct smuad {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct smulbb_smulbt_smultb_smultt {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_high;
        unsigned n;
        unsigned n_high;
    };

    struct smull {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct smulwb_smulwt {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_high;
        unsigned n;
    };

    struct smusd {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned m_swap;
        unsigned n;
    };

    struct srs_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned encoding;
        unsigned increment;
        unsigned mode;
        unsigned wback;
        unsigned wordhigher;
    };

    struct srs_thumb {
        unsigned W;
        unsigned encoding;
        unsigned increment;
        unsigned mode;
        unsigned wback;
        unsigned wordhigher;
    };

    struct ssat {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned saturate_to;
        unsigned shift_n;
        unsigned shift_t;
    };

    struct ssat16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned saturate_to;
    };

    struct ssax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct ssub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct ssub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct stc_stc2 {
        unsigned CRd;
        unsigned D;
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned coproc;
        unsigned cp;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned wback;
    };

    struct stm_stmia_stmea {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct stm_user_registers {
        unsigned P;
        unsigned U;
        unsigned cond;
        unsigned encoding;
        unsigned increment;
        unsigned n;
        unsigned registers;
        unsigned wordhigher;
    };

    struct stmda_stmed {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct stmdb_stmfd {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct stmib_stmfa {
        unsigned W;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned registers;
        unsigned wback;
    };

    struct str_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct str_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct str_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
        unsigned wback;
    };

    struct strb_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct strb_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct strb_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
        unsigned wback;
    };

    struct strbt {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
    };

    struct strd_immediate {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned t2;
        unsigned wback;
    };

    struct strd_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned t;
        unsigned t2;
        unsigned wback;
    };

    struct strex {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned t;
    };

    struct strexb {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned t;
    };

    struct strexd {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned t;
        unsigned t2;
    };

    struct strexh {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned t;
    };

    struct strh_immediate_arm {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct strh_immediate_thumb {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned encoding;
        unsigned imm32;
        unsigned index;
        unsigned n;
        unsigned t;
        unsigned wback;
    };

    struct strh_register {
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned wback;
    };

    struct strht {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned t;
    };

    struct strt {
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned postindex;
        unsigned register_form;
        unsigned shift_n;
        unsigned shift_t;
        unsigned t;
        unsigned type;
    };

    struct sub_immediate_arm {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct sub_immediate_thumb {
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned setflags;
    };

    struct sub_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct sub_register_shifted_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned setflags;
        unsigned shift_t;
        unsigned type;
    };

    struct sub_sp_minus_immediate {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned setflags;
    };

    struct sub_sp_minus_register {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned setflags;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct subs_pc_lr_and_related_instructions_arm {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned opcode_;
        unsigned register_form;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct subs_pc_lr_thumb {
        unsigned encoding;
        unsigned imm32;
        unsigned n;
    };

    struct svc {
        unsigned cond;
        unsigned encoding;
        unsigned imm32;
    };

    struct swp_swpb {
        unsigned B;
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned size;
        unsigned t;
        unsigned t2;
    };

    struct sxtab {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct sxtab16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct sxtah {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct sxtb {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct sxtb16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct sxth {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct tbb {
        unsigned encoding;
        unsigned is_tbh;
        unsigned m;
        unsigned n;
    };

    struct tbh {
        unsigned encoding;
        unsigned is_tbh;
        unsigned m;
        unsigned n;
    };

    struct teq_immediate {
        unsigned cond;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
    };

    struct teq_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct teq_register_shifted_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned shift_t;
        unsigned type;
    };

    struct tst_immediate {
        unsigned cond;
        unsigned encoding;
        unsigned imm12;
        unsigned imm32;
        unsigned n;
    };

    struct tst_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned shift_n;
        unsigned shift_t;
        unsigned type;
    };

    struct tst_register_shifted_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned s;
        unsigned shift_t;
        unsigned type;
    };

    struct uadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct ubfx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned lsbit;
        unsigned n;
        unsigned widthminus1;
    };

    struct udf {
        unsigned encoding;
        unsigned imm32;
    };

    struct udiv {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhsax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhsub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uhsub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct umaal {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct umlal {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct umull {
        unsigned cond;
        unsigned dHi;
        unsigned dLo;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned setflags;
    };

    struct uqadd16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uqadd8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uqasx {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uqsax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uqsub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uqsub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct usad8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct usada8 {
        unsigned a;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct usat {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned saturate_to;
        unsigned shift_n;
        unsigned shift_t;
    };

    struct usat16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned n;
        unsigned saturate_to;
    };

    struct usax {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct usub16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct usub8 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct uxtab {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct uxtab16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct uxtah {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned rotation;
    };

    struct uxtb {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct uxtb16 {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct uxth {
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned rotation;
    };

    struct vaba_vabal {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vabd_floating_point {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vabd_vabdl_integer {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vabs {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vacge_vacgt_vacle_vaclt {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned or_equal;
        unsigned regs;
    };

    struct vadd_floating_point {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vadd_integer {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
    };

    struct vaddhn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned size;
    };

    struct vaddl_vaddw {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned is_vaddw;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned size;
        unsigned unsigned_;
    };

    struct vand_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vbic_immediate {
        unsigned D;
        unsigned Q;
        unsigned cmode;
        unsigned d;
        unsigned encoding;
        unsigned imm64;
        unsigned regs;
    };

    struct vbic_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vbif_vbit_vbsl {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned operation;
        unsigned regs;
    };

    struct vceq_immediate_0 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vceq_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned int_operation;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
    };

    struct vcge_immediate_0 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vcge_register {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned type;
    };

    struct vcgt_immediate_0 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vcgt_register {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned type;
    };

    struct vcle_immediate_0 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vcls {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vclt_immediate_0 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vclz {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vcmp_vcmpe {
        unsigned D;
        unsigned E;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
        unsigned quiet_nan_exc;
        unsigned with_zero;
    };

    struct vcnt {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vcvt_between_double_precision_and_single_precision {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned double_to_single;
        unsigned encoding;
        unsigned m;
    };

    struct vcvt_between_floating_point_and_fixed_point_advancedsimd {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned frac_bits;
        unsigned imm32;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned round_nearest;
        unsigned round_zero;
        unsigned to_fixed;
        unsigned unsigned_;
    };

    struct vcvt_between_floating_point_and_fixed_point_floating_point {
        unsigned D;
        unsigned U;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned frac_bits;
        unsigned op;
        unsigned round_nearest;
        unsigned round_zero;
        unsigned size;
        unsigned to_fixed;
        unsigned unsigned_;
    };

    struct vcvt_between_floating_point_and_integer_advancedsimd {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned round_nearest;
        unsigned round_zero;
        unsigned size;
        unsigned to_integer;
        unsigned unsigned_;
    };

    struct vcvt_between_half_precision_and_single_precision_advancedsimd {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned half_to_single;
        unsigned m;
        unsigned op;
        unsigned size;
    };

    struct vcvt_vcvtr_between_floating_point_and_integer_floating_point {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
        unsigned op;
        unsigned opc2;
        unsigned round_nearest;
        unsigned round_zero;
        unsigned to_integer;
        unsigned unsigned_;
    };

    struct vcvtb_vcvtt {
        unsigned D;
        unsigned T;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned half_to_single;
        unsigned lowbit;
        unsigned m;
        unsigned op;
    };

    struct vdiv {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
        unsigned n;
    };

    struct vdup_arm_core_register {
        unsigned D;
        unsigned Q;
        unsigned cond;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned regs;
        unsigned t;
    };

    struct vdup_scalar {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned regs;
    };

    struct veor {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vext {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned m;
        unsigned n;
        unsigned position;
        unsigned quadword_operation;
    };

    struct vfma_vfms {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned op1_neg;
        unsigned regs;
    };

    struct vfnma_vfnms {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned op1_neg;
    };

    struct vhadd_vhsub {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned add;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vld1_multiple_single_elements {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned regs;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vld1_single_element_to_all_lanes {
        unsigned D;
        unsigned T;
        unsigned alignment;
        unsigned d;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned regs;
        unsigned size;
        unsigned wback;
    };

    struct vld1_single_element_to_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld2_multiple_2_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned regs;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vld2_single_2_element_structure_to_all_lanes {
        unsigned D;
        unsigned T;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld2_single_2_element_structure_to_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld3_multiple_3_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vld3_single_3_element_structure_to_all_lanes {
        unsigned D;
        unsigned T;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld3_single_3_element_structure_to_one_lane {
        unsigned D;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld4_multiple_4_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned d4;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vld4_single_4_element_structure_to_all_lanes {
        unsigned D;
        unsigned T;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned d4;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vld4_single_4_element_structure_to_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned d4;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vldm {
        unsigned D;
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned regs;
        unsigned single_regs;
        unsigned wback;
    };

    struct vldr {
        unsigned D;
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned single_reg;
    };

    struct vmax_vmin_floating_point {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned maximum;
        unsigned n;
        unsigned op;
        unsigned regs;
    };

    struct vmax_vmin_integer {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned maximum;
        unsigned n;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vmla_vmlal_vmls_vmlsl_by_scalar {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned add;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned index;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vmla_vmlal_vmls_vmlsl_integer {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned add;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vmla_vmls_floating_point {
        unsigned D;
        unsigned Q;
        unsigned add;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned regs;
    };

    struct vmov_arm_core_register_to_scalar {
        unsigned D;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned opc1;
        unsigned opc2;
        unsigned t;
    };

    struct vmov_between_arm_core_register_and_single_precision_register {
        unsigned cond;
        unsigned encoding;
        unsigned n;
        unsigned op;
        unsigned t;
        unsigned to_arm_register;
    };

    struct vmov_between_two_arm_core_registers_and_a_doubleword_extension_register {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned op;
        unsigned t;
        unsigned t2;
        unsigned to_arm_registers;
    };

    struct vmov_between_two_arm_core_registers_and_two_single_precision_registers {
        unsigned cond;
        unsigned encoding;
        unsigned m;
        unsigned op;
        unsigned t;
        unsigned t2;
        unsigned to_arm_registers;
    };

    struct vmov_immediate {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cmode;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned imm64;
        unsigned op;
        unsigned regs;
        unsigned single_register;
    };

    struct vmov_register {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned regs;
        unsigned single_register;
    };

    struct vmov_scalar_to_arm_core_register {
        unsigned U;
        unsigned advsimd;
        unsigned cond;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned n;
        unsigned opc1;
        unsigned opc2;
        unsigned t;
        unsigned unsigned_;
    };

    struct vmovl {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned unsigned_;
    };

    struct vmovn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned size;
    };

    struct vmrs {
        unsigned cond;
        unsigned encoding;
        unsigned reg;
        unsigned t;
    };

    struct vmsr {
        unsigned cond;
        unsigned encoding;
        unsigned reg;
        unsigned t;
    };

    struct vmul_floating_point {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vmul_vmull_by_scalar {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned index;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vmul_vmull_integer_and_polynomial {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned long_destination;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned polynomial;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vmvn_immediate {
        unsigned D;
        unsigned Q;
        unsigned cmode;
        unsigned d;
        unsigned encoding;
        unsigned imm64;
        unsigned regs;
    };

    struct vmvn_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vneg {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vnmla_vnmls_vnmul {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned type;
    };

    struct vorn_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vorr_immediate {
        unsigned D;
        unsigned Q;
        unsigned cmode;
        unsigned d;
        unsigned encoding;
        unsigned imm64;
        unsigned regs;
    };

    struct vorr_register {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vpadal {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vpadd_floating_point {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
    };

    struct vpadd_integer {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned size;
    };

    struct vpaddl {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vpmax_vpmin_floating_point {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned maximum;
        unsigned n;
        unsigned op;
    };

    struct vpmax_vpmin_integer {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned maximum;
        unsigned n;
        unsigned op;
        unsigned size;
        unsigned unsigned_;
    };

    struct vpop {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned regs;
        unsigned single_regs;
    };

    struct vpush {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned regs;
        unsigned single_regs;
    };

    struct vqabs {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vqadd {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vqdmlal_vqdmlsl {
        unsigned D;
        unsigned add;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned scalar_form;
        unsigned size;
    };

    struct vqdmulh {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned scalar_form;
        unsigned size;
    };

    struct vqdmull {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned scalar_form;
        unsigned size;
    };

    struct vqmovn_vqmovun {
        unsigned D;
        unsigned d;
        unsigned dest_unsigned;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned size;
        unsigned src_unsigned;
    };

    struct vqneg {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vqrdmulh {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned scalar_form;
        unsigned size;
    };

    struct vqrshl {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vqrshrn_vqrshrun {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned dest_unsigned;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned imm32;
        unsigned m;
        unsigned op;
        unsigned shift_amount;
        unsigned src_unsigned;
    };

    struct vqshl_register {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vqshl_vqshlu_immediate {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned dest_unsigned;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned shift_amount;
        unsigned src_unsigned;
    };

    struct vqshrn_vqshrun {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned dest_unsigned;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned op;
        unsigned shift_amount;
        unsigned src_unsigned;
    };

    struct vqsub {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vraddhn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned size;
    };

    struct vrecpe {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vrecps {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vrev16_vrev32_vrev64 {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned esize_minus_one;
        unsigned groupsize;
        unsigned groupsize_minus_one;
        unsigned m;
        unsigned op;
        unsigned regs;
        unsigned reverse_mask;
        unsigned size;
    };

    struct vrhadd {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vrshl {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vrshr {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
        unsigned unsigned_;
    };

    struct vrshrn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned shift_amount;
    };

    struct vrsqrte {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned floating_point;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vrsqrts {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vrsra {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
        unsigned unsigned_;
    };

    struct vrsubhn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned size;
    };

    struct vshl_immediate {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
    };

    struct vshl_register {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
        unsigned unsigned_;
    };

    struct vshll {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned shift_amount;
        unsigned size;
        unsigned unsigned_;
    };

    struct vshr {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
        unsigned unsigned_;
    };

    struct vshrn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned shift_amount;
    };

    struct vsli {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
    };

    struct vsqrt {
        unsigned D;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned encoding;
        unsigned m;
    };

    struct vsra {
        unsigned D;
        unsigned Q;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
        unsigned unsigned_;
    };

    struct vsri {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned shift_amount;
    };

    struct vst1_multiple_single_elements {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned regs;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vst1_single_element_from_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vst2_multiple_2_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned regs;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vst2_single_2_element_structure_from_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vst3_multiple_3_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vst3_single_3_element_structure_from_one_lane {
        unsigned D;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vst4_multiple_4_element_structures {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned d4;
        unsigned ebytes;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned type;
        unsigned wback;
    };

    struct vst4_single_4_element_structure_from_one_lane {
        unsigned D;
        unsigned alignment;
        unsigned d;
        unsigned d2;
        unsigned d3;
        unsigned d4;
        unsigned ebytes;
        unsigned encoding;
        unsigned esize;
        unsigned inc;
        unsigned index;
        unsigned m;
        unsigned n;
        unsigned register_index;
        unsigned size;
        unsigned wback;
    };

    struct vstm {
        unsigned D;
        unsigned P;
        unsigned U;
        unsigned W;
        unsigned add;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned regs;
        unsigned single_regs;
        unsigned wback;
    };

    struct vstr {
        unsigned D;
        unsigned U;
        unsigned add;
        unsigned cond;
        unsigned d;
        unsigned encoding;
        unsigned imm32;
        unsigned n;
        unsigned single_reg;
    };

    struct vsub_floating_point {
        unsigned D;
        unsigned Q;
        unsigned advsimd;
        unsigned cond;
        unsigned d;
        unsigned dp_operation;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
    };

    struct vsub_integer {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
    };

    struct vsubhn {
        unsigned D;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned size;
    };

    struct vsubl_vsubw {
        unsigned D;
        unsigned U;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned is_vsubw;
        unsigned m;
        unsigned n;
        unsigned op;
        unsigned size;
        unsigned unsigned_;
    };

    struct vswp {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vtbl_vtbx {
        unsigned D;
        unsigned d;
        unsigned encoding;
        unsigned is_vtbl;
        unsigned length;
        unsigned m;
        unsigned n;
        unsigned op;
    };

    struct vtrn {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned regs;
        unsigned size;
    };

    struct vtst {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned elements;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned n;
        unsigned regs;
        unsigned size;
    };

    struct vuzp {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned quadword_operation;
        unsigned size;
    };

    struct vzip {
        unsigned D;
        unsigned Q;
        unsigned d;
        unsigned encoding;
        unsigned esize;
        unsigned m;
        unsigned quadword_operation;
        unsigned size;
    };

    struct wfe {
        unsigned cond;
        unsigned encoding;
    };

    struct wfi {
        unsigned cond;
        unsigned encoding;
    };

    struct yield {
        unsigned cond;
        unsigned encoding;
    };

} m_fields;
