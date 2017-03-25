#include "arm/ARMContext.h"
#include "arm/ARMDisassembler.h"

#include <memory>

using namespace Disassembler;

class ARMInterpreter {
public:
    ARMInterpreter(ARMContext &ctx) :
        m_ctx{ctx} {
    }

    void execute(const ARMInstruction &ins);

private:
    ARMContext &m_ctx;

    bool ConditionPassed() { return true; }
    bool CurrentModeIsHyp() { return false; }
    bool CurrentModeIsNotUser() { return false; }
    bool EventRegistered() { return false; }
    bool HaveVirtExt() { return false; }
    bool IsSecure() { return false; }
    bool JazelleAcceptsExecution() { return false; }
    void BKPTInstrDebugEvent() {}
    void BranchWritePC(uint32_t address) {}
    void CheckAdvSIMDEnabled() {}
    void ClearEventRegister() {}
    void EncodingSpecificOperations() {}
    void Hint_Yield() {}
    void SwitchToJazelleExecution() {}
    void TakeHypTrapException() {}
    void WaitForEvent() {}
    void WaitForInterrupt() {}
    ARMMode CurrentInstrSet() { return ARMMode_ARM; }
    void SelectInstrSet(unsigned mode) {}
    void BXWritePC(unsigned address) {}
    void WriteHSR(unsigned ec, unsigned hsr_string) {}
    unsigned ThisInstr() { return 0; }
    bool Coproc_Accepted(unsigned cp_num, unsigned instr) { return true; }
    void GenerateCoprocessorException() {}
    void Coproc_InternalOperation(unsigned cp_num, unsigned instr) {}
    unsigned ProcessorID() { return 0; }
    void ClearExclusiveLocal(unsigned processorid) {}
    unsigned CountLeadingZeroBits(unsigned value) {return 0;}
    void CPSRWriteByInstr(unsigned value, unsigned byte_mask, bool is_exception_return) {}
    void SPSRWriteByInstr(unsigned value, unsigned byte_mask) {}
    void Hint_Debug(unsigned op) {}
    void DataMemoryBarrier(unsigned domain, unsigned types) {}
    void DataSynchronizationBarrier(unsigned domai, unsigned types) {}
    bool CurrentModeIsUserOrSystem() { return true; }
    bool HasVirtExt() { return true; }
    void CallHypervisor(unsigned immediate) {}
    void InstructionSynchronizationBarrier() {}
    void NullCheckIfThumbEE(unsigned n) {}
    void Coproc_SendLoadedWord(unsigned word, unsigned cp_num, unsigned instr) {}
    bool Coproc_DoneLoading(unsigned cp_num, unsigned instr) { return true; }
    void LoadWritePC(unsigned address) {}
    bool UnalignedSupport() { return false; }
    bool HaveLPAE() { return true; }
    bool BigEndian() {return false;}
    void SetExclusiveMonitors(unsigned address, unsigned size) {}
    void Coproc_SendOneWord(unsigned word, unsigned cp_num, unsigned instr) {}
    void Coproc_SendTwoWords(unsigned word2, unsigned word1, unsigned cp_num, unsigned instr) {}
    unsigned SInt(unsigned value, unsigned bitsize) { return value; }
    unsigned ArchVersion() { return 0; }
    bool Coproc_DoneStoring(unsigned cp_num, unsigned instr) { return true; }
    unsigned Coproc_GetOneWord(unsigned cp_num, unsigned instr) { return 0;}
    std::tuple<unsigned, unsigned >Coproc_GetTwoWords(unsigned cp_num, unsigned instr) { return std::tuple<unsigned, unsigned>(0, 0); }
    unsigned Coproc_GetWordToStore(unsigned cp_num, unsigned instr) { return 0; }
    void BankedRegisterAccessValid(unsigned SYSm, unsigned mode) {}
    void SPSRaccessValid(unsigned SYSm, unsigned mode) {}
    void Hint_PreloadDataForWrite(unsigned address) {}
    void Hint_PreloadData(unsigned address) {}
    void Hint_PreloadInstr(unsigned address) {}
    unsigned LowestSetBit(unsigned value) { return 0; }
    unsigned PCStoreValue() { return 0; }
    std::tuple<unsigned, bool> SignedSatQ(unsigned i, unsigned N) { return std::tuple<unsigned, unsigned>(0, false);}
    std::tuple<unsigned, bool> UnsignedSatQ(unsigned i, unsigned N) { return std::tuple<unsigned, unsigned>(0, false); }
    unsigned SignedSat(unsigned i, unsigned N) { return i; }
    unsigned UnsignedSat(unsigned i, unsigned N) { return i; }
    std::tuple<unsigned, bool> SatQ(unsigned i, unsigned N, bool unsigned_) { return std::tuple<unsigned, unsigned>(0, false); }
    unsigned Sat(unsigned i, unsigned N, bool unsigned_) { return 0; }
    bool IntegerZeroDivideTrappingEnabled() { return false; }
    void GenerateIntegerZeroDivide() {}
    unsigned RoundTowardsZero(unsigned val) { return val; }
    void SendEvent() {}
    bool HaveSecurityExt() { return true; }
    void TakeSMCException() {}
    bool ExclusiveMonitorsPass(unsigned address, unsigned size) { return false; }
    void CallSupervisor(unsigned immediate) {}
    unsigned Abs(unsigned value) { return value; }
    bool CheckAdvSIMDOrVFPEnabled(bool include_fpexc_check, bool advsimd) { return true; }
    unsigned FPAbs(unsigned operand) { return operand; }
    void CheckVFPEnabled(bool value) { }
    unsigned FPHalfToSingle(unsigned short operand, bool fpscr_controlled) { return 0; }
    unsigned short FPSingleToHalf(unsigned operand, bool fpscr_controlled) { return 0; }
    uint64_t FPSingleToDouble(uint32_t operand, bool fpscr_controlled) { return 0; }
    uint32_t FPDoubleToSingle(uint64_t operand, bool fpscr_controlled) { return 0; }
    unsigned FPMul(unsigned op1, unsigned op2, bool fpscr_controlled) { return 0; }
    unsigned FPDiv(unsigned op1, unsigned op2, bool fpscr_controlled) { return 0; }
    unsigned FPMulAdd(unsigned addend, unsigned op1, unsigned op2, bool fpscr_controlled) { return 0; }
    unsigned FPNeg(unsigned operand) { return 0; }
    void GenerateAlignmentException() {}
    unsigned FixedToFP(unsigned operand, unsigned N, unsigned fraction_bits, bool unsigned_, bool round_to_nearest, bool fpscr_controlled) { return 0; }
    unsigned FPToFixed(unsigned operand, unsigned M, unsigned fraction_bits, unsigned unsigned_, bool round_towards_zero, bool fpscr_controlled) { return 0; }
    unsigned CountLeadingSignBits(unsigned val) { return 0; }
    unsigned FPZero(unsigned sign, unsigned N) { return 0; }
    unsigned FPTwo(unsigned N) { return 0; }
    unsigned FPThree(unsigned N) { return 0; }
    unsigned FPMaxNormal(unsigned sign, unsigned N) { return 0; }
    unsigned FPInfinity(unsigned sign, unsigned N) { return 0; }
    unsigned FPDefaultNaN(unsigned N) { return 0; }
    unsigned FPAdd(unsigned op1, unsigned op2, bool fpscr_controlled) { return 0; }
    unsigned FPSub(unsigned op1, unsigned op2, bool fpscr_controlled) { return 0; }
    bool FPCompareGT(unsigned op1, unsigned op2, bool fpscr_controlled) { return false; }
    void SerializeVFP() {}
    void VFPExcBarrier() {}
    unsigned Ones(unsigned n) { return 0; }
    void NullCheckIfThumbEE() {}
    unsigned FPSqrt(unsigned operand) { return 0; }
    unsigned FPRSqrtStep(unsigned op1, unsigned op2) { return 0; }
    unsigned UnsignedRSqrtEstimate(unsigned operand) { return 0; }
    unsigned FPRSqrtEstimate(unsigned operand) { return 0; }
    unsigned FPRecipStep(unsigned op1, unsigned op2) { return 0; }
    unsigned UnsignedRecipEstimate(unsigned operand) { return 0; }
    unsigned FPRecipEstimate(unsigned operand) { return 0; }
    bool FPCompareGE(unsigned op1, unsigned op2, bool fpscr_controlled) { return false; }
    std::tuple<bool, bool, bool, bool> FPCompare(unsigned op1, unsigned op2, bool quiet_nan_exc, bool fpscr_controlled) { return std::tuple<bool, bool, bool, bool>(false, false, false, false); }
    bool FPCompareEQ(unsigned op1, unsigned op2, bool fpscr_controlled) { return false; }
    template<class T> const T& Max(const T& a, const T& b) { return (a < b) ? b : a; }
    template<class T> const T& Min(const T& a, const T& b) { return (a < b) ? a : b; }
    template<class T> const T& FPMax(const T& a, const T& b, bool val) { return (a < b) ? b : a; }
    template<class T> const T& FPMin(const T& a, const T& b, bool val) { return (a < b) ? a : b; }
    unsigned PolynomialMult(unsigned op1, unsigned op2) { return 0; }

    bool interpret_adc_immediate(const ARMInstruction &ins);
    bool interpret_adc_register(const ARMInstruction &ins);
    bool interpret_adc_register_shifted_register(const ARMInstruction &ins);
    bool interpret_add_immediate_thumb(const ARMInstruction &ins);
    bool interpret_add_immediate_arm(const ARMInstruction &ins);
    bool interpret_add_register_thumb(const ARMInstruction &ins);
    bool interpret_add_register_arm(const ARMInstruction &ins);
    bool interpret_add_register_shifted_register(const ARMInstruction &ins);
    bool interpret_add_sp_plus_immediate(const ARMInstruction &ins);
    bool interpret_add_sp_plus_register_thumb(const ARMInstruction &ins);
    bool interpret_add_sp_plus_register_arm(const ARMInstruction &ins);
    bool interpret_adr(const ARMInstruction &ins);
    bool interpret_and_immediate(const ARMInstruction &ins);
    bool interpret_and_register(const ARMInstruction &ins);
    bool interpret_and_register_shifted_register(const ARMInstruction &ins);
    bool interpret_asr_immediate(const ARMInstruction &ins);
    bool interpret_asr_register(const ARMInstruction &ins);
    bool interpret_b(const ARMInstruction &ins);
    bool interpret_bfc(const ARMInstruction &ins);
    bool interpret_bfi(const ARMInstruction &ins);
    bool interpret_bic_immediate(const ARMInstruction &ins);
    bool interpret_bic_register(const ARMInstruction &ins);
    bool interpret_bic_register_shifted_register(const ARMInstruction &ins);
    bool interpret_bkpt(const ARMInstruction &ins);
    bool interpret_bl_blx_immediate(const ARMInstruction &ins);
    bool interpret_blx_register(const ARMInstruction &ins);
    bool interpret_bx(const ARMInstruction &ins);
    bool interpret_bxj(const ARMInstruction &ins);
    bool interpret_cbnz_cbz(const ARMInstruction &ins);
    bool interpret_cdp_cdp2(const ARMInstruction &ins);
    bool interpret_clrex(const ARMInstruction &ins);
    bool interpret_clz(const ARMInstruction &ins);
    bool interpret_cmn_immediate(const ARMInstruction &ins);
    bool interpret_cmn_register(const ARMInstruction &ins);
    bool interpret_cmn_register_shifted_register(const ARMInstruction &ins);
    bool interpret_cmp_immediate(const ARMInstruction &ins);
    bool interpret_cmp_register(const ARMInstruction &ins);
    bool interpret_cmp_register_shifted_register(const ARMInstruction &ins);
    bool interpret_cps_thumb(const ARMInstruction &ins);
    bool interpret_cps_arm(const ARMInstruction &ins);
    bool interpret_dbg(const ARMInstruction &ins);
    bool interpret_dmb(const ARMInstruction &ins);
    bool interpret_dsb(const ARMInstruction &ins);
    bool interpret_eor_immediate(const ARMInstruction &ins);
    bool interpret_eor_register(const ARMInstruction &ins);
    bool interpret_eor_register_shifted_register(const ARMInstruction &ins);
    bool interpret_eret(const ARMInstruction &ins);
    bool interpret_hvc(const ARMInstruction &ins);
    bool interpret_isb(const ARMInstruction &ins);
    bool interpret_it(const ARMInstruction &ins);
    bool interpret_ldc_ldc2_immediate(const ARMInstruction &ins);
    bool interpret_ldc_ldc2_literal(const ARMInstruction &ins);
    bool interpret_ldm_ldmia_ldmfd_thumb(const ARMInstruction &ins);
    bool interpret_ldm_ldmia_ldmfd_arm(const ARMInstruction &ins);
    bool interpret_ldmda_ldmfa(const ARMInstruction &ins);
    bool interpret_ldmdb_ldmea(const ARMInstruction &ins);
    bool interpret_ldmib_ldmed(const ARMInstruction &ins);
    bool interpret_ldr_immediate_thumb(const ARMInstruction &ins);
    bool interpret_ldr_immediate_arm(const ARMInstruction &ins);
    bool interpret_ldr_literal(const ARMInstruction &ins);
    bool interpret_ldr_register_thumb(const ARMInstruction &ins);
    bool interpret_ldr_register_arm(const ARMInstruction &ins);
    bool interpret_ldrb_immediate_thumb(const ARMInstruction &ins);
    bool interpret_ldrb_immediate_arm(const ARMInstruction &ins);
    bool interpret_ldrb_literal(const ARMInstruction &ins);
    bool interpret_ldrb_register(const ARMInstruction &ins);
    bool interpret_ldrbt(const ARMInstruction &ins);
    bool interpret_ldrd_immediate(const ARMInstruction &ins);
    bool interpret_ldrd_literal(const ARMInstruction &ins);
    bool interpret_ldrd_register(const ARMInstruction &ins);
    bool interpret_ldrex(const ARMInstruction &ins);
    bool interpret_ldrexb(const ARMInstruction &ins);
    bool interpret_ldrexd(const ARMInstruction &ins);
    bool interpret_ldrexh(const ARMInstruction &ins);
    bool interpret_ldrh_immediate_thumb(const ARMInstruction &ins);
    bool interpret_ldrh_immediate_arm(const ARMInstruction &ins);
    bool interpret_ldrh_literal(const ARMInstruction &ins);
    bool interpret_ldrh_register(const ARMInstruction &ins);
    bool interpret_ldrht(const ARMInstruction &ins);
    bool interpret_ldrsb_immediate(const ARMInstruction &ins);
    bool interpret_ldrsb_literal(const ARMInstruction &ins);
    bool interpret_ldrsb_register(const ARMInstruction &ins);
    bool interpret_ldrsbt(const ARMInstruction &ins);
    bool interpret_ldrsh_immediate(const ARMInstruction &ins);
    bool interpret_ldrsh_literal(const ARMInstruction &ins);
    bool interpret_ldrsh_register(const ARMInstruction &ins);
    bool interpret_ldrsht(const ARMInstruction &ins);
    bool interpret_ldrt(const ARMInstruction &ins);
    bool interpret_lsl_immediate(const ARMInstruction &ins);
    bool interpret_lsl_register(const ARMInstruction &ins);
    bool interpret_lsr_immediate(const ARMInstruction &ins);
    bool interpret_lsr_register(const ARMInstruction &ins);
    bool interpret_mcr_mcr2(const ARMInstruction &ins);
    bool interpret_mcrr_mcrr2(const ARMInstruction &ins);
    bool interpret_mla(const ARMInstruction &ins);
    bool interpret_mls(const ARMInstruction &ins);
    bool interpret_mov_immediate(const ARMInstruction &ins);
    bool interpret_mov_register_thumb(const ARMInstruction &ins);
    bool interpret_mov_register_arm(const ARMInstruction &ins);
    bool interpret_movt(const ARMInstruction &ins);
    bool interpret_mrc_mrc2(const ARMInstruction &ins);
    bool interpret_mrrc_mrrc2(const ARMInstruction &ins);
    bool interpret_mrs(const ARMInstruction &ins);
    bool interpret_mrs_banked_register(const ARMInstruction &ins);
    bool interpret_msr_immediate(const ARMInstruction &ins);
    bool interpret_msr_register(const ARMInstruction &ins);
    bool interpret_mul(const ARMInstruction &ins);
    bool interpret_mvn_immediate(const ARMInstruction &ins);
    bool interpret_mvn_register(const ARMInstruction &ins);
    bool interpret_mvn_register_shifted_register(const ARMInstruction &ins);
    bool interpret_nop(const ARMInstruction &ins);
    bool interpret_orn_immediate(const ARMInstruction &ins);
    bool interpret_orn_register(const ARMInstruction &ins);
    bool interpret_orr_immediate(const ARMInstruction &ins);
    bool interpret_orr_register(const ARMInstruction &ins);
    bool interpret_orr_register_shifted_register(const ARMInstruction &ins);
    bool interpret_pkh(const ARMInstruction &ins);
    bool interpret_pld_pldw_immediate(const ARMInstruction &ins);
    bool interpret_pld_literal(const ARMInstruction &ins);
    bool interpret_pld_pldw_register(const ARMInstruction &ins);
    bool interpret_pli_immediate_literal(const ARMInstruction &ins);
    bool interpret_pli_register(const ARMInstruction &ins);
    bool interpret_pop_thumb(const ARMInstruction &ins);
    bool interpret_pop_arm(const ARMInstruction &ins);
    bool interpret_push(const ARMInstruction &ins);
    bool interpret_qadd(const ARMInstruction &ins);
    bool interpret_qadd16(const ARMInstruction &ins);
    bool interpret_qadd8(const ARMInstruction &ins);
    bool interpret_qasx(const ARMInstruction &ins);
    bool interpret_qdadd(const ARMInstruction &ins);
    bool interpret_qdsub(const ARMInstruction &ins);
    bool interpret_qsax(const ARMInstruction &ins);
    bool interpret_qsub(const ARMInstruction &ins);
    bool interpret_qsub16(const ARMInstruction &ins);
    bool interpret_qsub8(const ARMInstruction &ins);
    bool interpret_rbit(const ARMInstruction &ins);
    bool interpret_rev(const ARMInstruction &ins);
    bool interpret_rev16(const ARMInstruction &ins);
    bool interpret_revsh(const ARMInstruction &ins);
    bool interpret_rfe(const ARMInstruction &ins);
    bool interpret_ror_immediate(const ARMInstruction &ins);
    bool interpret_ror_register(const ARMInstruction &ins);
    bool interpret_rrx(const ARMInstruction &ins);
    bool interpret_rsb_immediate(const ARMInstruction &ins);
    bool interpret_rsb_register(const ARMInstruction &ins);
    bool interpret_rsb_register_shifted_register(const ARMInstruction &ins);
    bool interpret_rsc_immediate(const ARMInstruction &ins);
    bool interpret_rsc_register(const ARMInstruction &ins);
    bool interpret_rsc_register_shifted_register(const ARMInstruction &ins);
    bool interpret_sadd16(const ARMInstruction &ins);
    bool interpret_sadd8(const ARMInstruction &ins);
    bool interpret_sasx(const ARMInstruction &ins);
    bool interpret_sbc_immediate(const ARMInstruction &ins);
    bool interpret_sbc_register(const ARMInstruction &ins);
    bool interpret_sbc_register_shifted_register(const ARMInstruction &ins);
    bool interpret_sbfx(const ARMInstruction &ins);
    bool interpret_sdiv(const ARMInstruction &ins);
    bool interpret_sel(const ARMInstruction &ins);
    bool interpret_setend(const ARMInstruction &ins);
    bool interpret_sev(const ARMInstruction &ins);
    bool interpret_shadd16(const ARMInstruction &ins);
    bool interpret_shadd8(const ARMInstruction &ins);
    bool interpret_shasx(const ARMInstruction &ins);
    bool interpret_shsax(const ARMInstruction &ins);
    bool interpret_shsub16(const ARMInstruction &ins);
    bool interpret_shsub8(const ARMInstruction &ins);
    bool interpret_smc_previously_smi(const ARMInstruction &ins);
    bool interpret_smlabb_smlabt_smlatb_smlatt(const ARMInstruction &ins);
    bool interpret_smlad(const ARMInstruction &ins);
    bool interpret_smlal(const ARMInstruction &ins);
    bool interpret_smlalbb_smlalbt_smlaltb_smlaltt(const ARMInstruction &ins);
    bool interpret_smlald(const ARMInstruction &ins);
    bool interpret_smlawb_smlawt(const ARMInstruction &ins);
    bool interpret_smlsd(const ARMInstruction &ins);
    bool interpret_smlsld(const ARMInstruction &ins);
    bool interpret_smmla(const ARMInstruction &ins);
    bool interpret_smmls(const ARMInstruction &ins);
    bool interpret_smmul(const ARMInstruction &ins);
    bool interpret_smuad(const ARMInstruction &ins);
    bool interpret_smulbb_smulbt_smultb_smultt(const ARMInstruction &ins);
    bool interpret_smull(const ARMInstruction &ins);
    bool interpret_smulwb_smulwt(const ARMInstruction &ins);
    bool interpret_smusd(const ARMInstruction &ins);
    bool interpret_srs_thumb(const ARMInstruction &ins);
    bool interpret_srs_arm(const ARMInstruction &ins);
    bool interpret_ssat(const ARMInstruction &ins);
    bool interpret_ssat16(const ARMInstruction &ins);
    bool interpret_ssax(const ARMInstruction &ins);
    bool interpret_ssub16(const ARMInstruction &ins);
    bool interpret_ssub8(const ARMInstruction &ins);
    bool interpret_stc_stc2(const ARMInstruction &ins);
    bool interpret_stm_stmia_stmea(const ARMInstruction &ins);
    bool interpret_stmda_stmed(const ARMInstruction &ins);
    bool interpret_stmdb_stmfd(const ARMInstruction &ins);
    bool interpret_stmib_stmfa(const ARMInstruction &ins);
    bool interpret_str_immediate_thumb(const ARMInstruction &ins);
    bool interpret_str_immediate_arm(const ARMInstruction &ins);
    bool interpret_str_register(const ARMInstruction &ins);
    bool interpret_strb_immediate_thumb(const ARMInstruction &ins);
    bool interpret_strb_immediate_arm(const ARMInstruction &ins);
    bool interpret_strb_register(const ARMInstruction &ins);
    bool interpret_strbt(const ARMInstruction &ins);
    bool interpret_strd_immediate(const ARMInstruction &ins);
    bool interpret_strd_register(const ARMInstruction &ins);
    bool interpret_strex(const ARMInstruction &ins);
    bool interpret_strexb(const ARMInstruction &ins);
    bool interpret_strexd(const ARMInstruction &ins);
    bool interpret_strexh(const ARMInstruction &ins);
    bool interpret_strh_immediate_thumb(const ARMInstruction &ins);
    bool interpret_strh_immediate_arm(const ARMInstruction &ins);
    bool interpret_strh_register(const ARMInstruction &ins);
    bool interpret_strht(const ARMInstruction &ins);
    bool interpret_strt(const ARMInstruction &ins);
    bool interpret_sub_immediate_thumb(const ARMInstruction &ins);
    bool interpret_sub_immediate_arm(const ARMInstruction &ins);
    bool interpret_sub_register(const ARMInstruction &ins);
    bool interpret_sub_register_shifted_register(const ARMInstruction &ins);
    bool interpret_sub_sp_minus_immediate(const ARMInstruction &ins);
    bool interpret_sub_sp_minus_register(const ARMInstruction &ins);
    bool interpret_subs_pc_lr_thumb(const ARMInstruction &ins);
    bool interpret_subs_pc_lr_and_related_instructions_arm(const ARMInstruction &ins);
    bool interpret_svc(const ARMInstruction &ins);
    bool interpret_swp_swpb(const ARMInstruction &ins);
    bool interpret_sxtab(const ARMInstruction &ins);
    bool interpret_sxtab16(const ARMInstruction &ins);
    bool interpret_sxtah(const ARMInstruction &ins);
    bool interpret_sxtb(const ARMInstruction &ins);
    bool interpret_sxtb16(const ARMInstruction &ins);
    bool interpret_sxth(const ARMInstruction &ins);
    bool interpret_tbb(const ARMInstruction &ins);
    bool interpret_tbh(const ARMInstruction &ins);
    bool interpret_teq_immediate(const ARMInstruction &ins);
    bool interpret_teq_register(const ARMInstruction &ins);
    bool interpret_teq_register_shifted_register(const ARMInstruction &ins);
    bool interpret_tst_immediate(const ARMInstruction &ins);
    bool interpret_tst_register(const ARMInstruction &ins);
    bool interpret_tst_register_shifted_register(const ARMInstruction &ins);
    bool interpret_uadd16(const ARMInstruction &ins);
    bool interpret_uadd8(const ARMInstruction &ins);
    bool interpret_uasx(const ARMInstruction &ins);
    bool interpret_ubfx(const ARMInstruction &ins);
    bool interpret_udf(const ARMInstruction &ins);
    bool interpret_udiv(const ARMInstruction &ins);
    bool interpret_uhadd16(const ARMInstruction &ins);
    bool interpret_uhadd8(const ARMInstruction &ins);
    bool interpret_uhasx(const ARMInstruction &ins);
    bool interpret_uhsax(const ARMInstruction &ins);
    bool interpret_uhsub16(const ARMInstruction &ins);
    bool interpret_uhsub8(const ARMInstruction &ins);
    bool interpret_umaal(const ARMInstruction &ins);
    bool interpret_umlal(const ARMInstruction &ins);
    bool interpret_umull(const ARMInstruction &ins);
    bool interpret_uqadd16(const ARMInstruction &ins);
    bool interpret_uqadd8(const ARMInstruction &ins);
    bool interpret_uqasx(const ARMInstruction &ins);
    bool interpret_uqsax(const ARMInstruction &ins);
    bool interpret_uqsub16(const ARMInstruction &ins);
    bool interpret_uqsub8(const ARMInstruction &ins);
    bool interpret_usad8(const ARMInstruction &ins);
    bool interpret_usada8(const ARMInstruction &ins);
    bool interpret_usat(const ARMInstruction &ins);
    bool interpret_usat16(const ARMInstruction &ins);
    bool interpret_usax(const ARMInstruction &ins);
    bool interpret_usub16(const ARMInstruction &ins);
    bool interpret_usub8(const ARMInstruction &ins);
    bool interpret_uxtab(const ARMInstruction &ins);
    bool interpret_uxtab16(const ARMInstruction &ins);
    bool interpret_uxtah(const ARMInstruction &ins);
    bool interpret_uxtb(const ARMInstruction &ins);
    bool interpret_uxtb16(const ARMInstruction &ins);
    bool interpret_uxth(const ARMInstruction &ins);
    bool interpret_vaba_vabal(const ARMInstruction &ins);
    bool interpret_vabd_vabdl_integer(const ARMInstruction &ins);
    bool interpret_vabd_floating_point(const ARMInstruction &ins);
    bool interpret_vabs(const ARMInstruction &ins);
    bool interpret_vacge_vacgt_vacle_vaclt(const ARMInstruction &ins);
    bool interpret_vadd_integer(const ARMInstruction &ins);
    bool interpret_vadd_floating_point(const ARMInstruction &ins);
    bool interpret_vaddhn(const ARMInstruction &ins);
    bool interpret_vaddl_vaddw(const ARMInstruction &ins);
    bool interpret_vand_register(const ARMInstruction &ins);
    bool interpret_vbic_immediate(const ARMInstruction &ins);
    bool interpret_vbic_register(const ARMInstruction &ins);
    bool interpret_vbif_vbit_vbsl(const ARMInstruction &ins);
    bool interpret_vceq_register(const ARMInstruction &ins);
    bool interpret_vceq_immediate_0(const ARMInstruction &ins);
    bool interpret_vcge_register(const ARMInstruction &ins);
    bool interpret_vcge_immediate_0(const ARMInstruction &ins);
    bool interpret_vcgt_register(const ARMInstruction &ins);
    bool interpret_vcgt_immediate_0(const ARMInstruction &ins);
    bool interpret_vcle_immediate_0(const ARMInstruction &ins);
    bool interpret_vcls(const ARMInstruction &ins);
    bool interpret_vclt_immediate_0(const ARMInstruction &ins);
    bool interpret_vclz(const ARMInstruction &ins);
    bool interpret_vcmp_vcmpe(const ARMInstruction &ins);
    bool interpret_vcnt(const ARMInstruction &ins);
    bool interpret_vcvt_between_floating_point_and_integer_advancedsimd(const ARMInstruction &ins);
    bool interpret_vcvt_vcvtr_between_floating_point_and_integer_floating_point(const ARMInstruction &ins);
    bool interpret_vcvt_between_floating_point_and_fixed_point_advancedsimd(const ARMInstruction &ins);
    bool interpret_vcvt_between_floating_point_and_fixed_point_floating_point(const ARMInstruction &ins);
    bool interpret_vcvt_between_double_precision_and_single_precision(const ARMInstruction &ins);
    bool interpret_vcvt_between_half_precision_and_single_precision_advancedsimd(const ARMInstruction &ins);
    bool interpret_vcvtb_vcvtt(const ARMInstruction &ins);
    bool interpret_vdiv(const ARMInstruction &ins);
    bool interpret_vdup_scalar(const ARMInstruction &ins);
    bool interpret_vdup_arm_core_register(const ARMInstruction &ins);
    bool interpret_veor(const ARMInstruction &ins);
    bool interpret_vext(const ARMInstruction &ins);
    bool interpret_vfma_vfms(const ARMInstruction &ins);
    bool interpret_vfnma_vfnms(const ARMInstruction &ins);
    bool interpret_vhadd_vhsub(const ARMInstruction &ins);
    bool interpret_vld1_multiple_single_elements(const ARMInstruction &ins);
    bool interpret_vld1_single_element_to_one_lane(const ARMInstruction &ins);
    bool interpret_vld1_single_element_to_all_lanes(const ARMInstruction &ins);
    bool interpret_vld2_multiple_2_element_structures(const ARMInstruction &ins);
    bool interpret_vld2_single_2_element_structure_to_one_lane(const ARMInstruction &ins);
    bool interpret_vld2_single_2_element_structure_to_all_lanes(const ARMInstruction &ins);
    bool interpret_vld3_multiple_3_element_structures(const ARMInstruction &ins);
    bool interpret_vld3_single_3_element_structure_to_one_lane(const ARMInstruction &ins);
    bool interpret_vld3_single_3_element_structure_to_all_lanes(const ARMInstruction &ins);
    bool interpret_vld4_multiple_4_element_structures(const ARMInstruction &ins);
    bool interpret_vld4_single_4_element_structure_to_one_lane(const ARMInstruction &ins);
    bool interpret_vld4_single_4_element_structure_to_all_lanes(const ARMInstruction &ins);
    bool interpret_vldm(const ARMInstruction &ins);
    bool interpret_vldr(const ARMInstruction &ins);
    bool interpret_vmax_vmin_integer(const ARMInstruction &ins);
    bool interpret_vmax_vmin_floating_point(const ARMInstruction &ins);
    bool interpret_vmla_vmlal_vmls_vmlsl_integer(const ARMInstruction &ins);
    bool interpret_vmla_vmls_floating_point(const ARMInstruction &ins);
    bool interpret_vmla_vmlal_vmls_vmlsl_by_scalar(const ARMInstruction &ins);
    bool interpret_vmov_immediate(const ARMInstruction &ins);
    bool interpret_vmov_register(const ARMInstruction &ins);
    bool interpret_vmov_arm_core_register_to_scalar(const ARMInstruction &ins);
    bool interpret_vmov_scalar_to_arm_core_register(const ARMInstruction &ins);
    bool interpret_vmov_between_arm_core_register_and_single_precision_register(const ARMInstruction &ins);
    bool interpret_vmov_between_two_arm_core_registers_and_two_single_precision_registers(const ARMInstruction &ins);
    bool interpret_vmov_between_two_arm_core_registers_and_a_doubleword_extension_register(const ARMInstruction &ins);
    bool interpret_vmovl(const ARMInstruction &ins);
    bool interpret_vmovn(const ARMInstruction &ins);
    bool interpret_vmrs(const ARMInstruction &ins);
    bool interpret_vmsr(const ARMInstruction &ins);
    bool interpret_vmul_vmull_integer_and_polynomial(const ARMInstruction &ins);
    bool interpret_vmul_floating_point(const ARMInstruction &ins);
    bool interpret_vmul_vmull_by_scalar(const ARMInstruction &ins);
    bool interpret_vmvn_immediate(const ARMInstruction &ins);
    bool interpret_vmvn_register(const ARMInstruction &ins);
    bool interpret_vneg(const ARMInstruction &ins);
    bool interpret_vnmla_vnmls_vnmul(const ARMInstruction &ins);
    bool interpret_vorn_register(const ARMInstruction &ins);
    bool interpret_vorr_immediate(const ARMInstruction &ins);
    bool interpret_vorr_register(const ARMInstruction &ins);
    bool interpret_vpadal(const ARMInstruction &ins);
    bool interpret_vpadd_integer(const ARMInstruction &ins);
    bool interpret_vpadd_floating_point(const ARMInstruction &ins);
    bool interpret_vpaddl(const ARMInstruction &ins);
    bool interpret_vpmax_vpmin_integer(const ARMInstruction &ins);
    bool interpret_vpmax_vpmin_floating_point(const ARMInstruction &ins);
    bool interpret_vpop(const ARMInstruction &ins);
    bool interpret_vpush(const ARMInstruction &ins);
    bool interpret_vqabs(const ARMInstruction &ins);
    bool interpret_vqadd(const ARMInstruction &ins);
    bool interpret_vqdmlal_vqdmlsl(const ARMInstruction &ins);
    bool interpret_vqdmulh(const ARMInstruction &ins);
    bool interpret_vqdmull(const ARMInstruction &ins);
    bool interpret_vqmovn_vqmovun(const ARMInstruction &ins);
    bool interpret_vqneg(const ARMInstruction &ins);
    bool interpret_vqrdmulh(const ARMInstruction &ins);
    bool interpret_vqrshl(const ARMInstruction &ins);
    bool interpret_vqrshrn_vqrshrun(const ARMInstruction &ins);
    bool interpret_vqshl_register(const ARMInstruction &ins);
    bool interpret_vqshl_vqshlu_immediate(const ARMInstruction &ins);
    bool interpret_vqshrn_vqshrun(const ARMInstruction &ins);
    bool interpret_vqsub(const ARMInstruction &ins);
    bool interpret_vraddhn(const ARMInstruction &ins);
    bool interpret_vrecpe(const ARMInstruction &ins);
    bool interpret_vrecps(const ARMInstruction &ins);
    bool interpret_vrev16_vrev32_vrev64(const ARMInstruction &ins);
    bool interpret_vrhadd(const ARMInstruction &ins);
    bool interpret_vrshl(const ARMInstruction &ins);
    bool interpret_vrshr(const ARMInstruction &ins);
    bool interpret_vrshrn(const ARMInstruction &ins);
    bool interpret_vrsqrte(const ARMInstruction &ins);
    bool interpret_vrsqrts(const ARMInstruction &ins);
    bool interpret_vrsra(const ARMInstruction &ins);
    bool interpret_vrsubhn(const ARMInstruction &ins);
    bool interpret_vshl_immediate(const ARMInstruction &ins);
    bool interpret_vshl_register(const ARMInstruction &ins);
    bool interpret_vshll(const ARMInstruction &ins);
    bool interpret_vshr(const ARMInstruction &ins);
    bool interpret_vshrn(const ARMInstruction &ins);
    bool interpret_vsli(const ARMInstruction &ins);
    bool interpret_vsqrt(const ARMInstruction &ins);
    bool interpret_vsra(const ARMInstruction &ins);
    bool interpret_vsri(const ARMInstruction &ins);
    bool interpret_vst1_multiple_single_elements(const ARMInstruction &ins);
    bool interpret_vst1_single_element_from_one_lane(const ARMInstruction &ins);
    bool interpret_vst2_multiple_2_element_structures(const ARMInstruction &ins);
    bool interpret_vst2_single_2_element_structure_from_one_lane(const ARMInstruction &ins);
    bool interpret_vst3_multiple_3_element_structures(const ARMInstruction &ins);
    bool interpret_vst3_single_3_element_structure_from_one_lane(const ARMInstruction &ins);
    bool interpret_vst4_multiple_4_element_structures(const ARMInstruction &ins);
    bool interpret_vst4_single_4_element_structure_from_one_lane(const ARMInstruction &ins);
    bool interpret_vstm(const ARMInstruction &ins);
    bool interpret_vstr(const ARMInstruction &ins);
    bool interpret_vsub_integer(const ARMInstruction &ins);
    bool interpret_vsub_floating_point(const ARMInstruction &ins);
    bool interpret_vsubhn(const ARMInstruction &ins);
    bool interpret_vsubl_vsubw(const ARMInstruction &ins);
    bool interpret_vswp(const ARMInstruction &ins);
    bool interpret_vtbl_vtbx(const ARMInstruction &ins);
    bool interpret_vtrn(const ARMInstruction &ins);
    bool interpret_vtst(const ARMInstruction &ins);
    bool interpret_vuzp(const ARMInstruction &ins);
    bool interpret_vzip(const ARMInstruction &ins);
    bool interpret_wfe(const ARMInstruction &ins);
    bool interpret_wfi(const ARMInstruction &ins);
    bool interpret_yield(const ARMInstruction &ins);
};
