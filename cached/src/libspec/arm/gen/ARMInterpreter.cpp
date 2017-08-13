#include "arm/gen/ARMInterpreter.h"
#include "arm/gen/ARMDecodingTable.h"
#include "arm/ARMContext.h"
#include "arm/ARMUtilities.h"
#include "Utilities.h"

#include <tuple>
#include <memory>

using namespace std;

void ARMInterpreter::execute(const ARMInstruction &ins) {
    switch (ins.id) {
        case ARMInstructionId::adc_immediate: interpret_adc_immediate(ins); break;
        case ARMInstructionId::adc_register: interpret_adc_register(ins); break;
        case ARMInstructionId::adc_register_shifted_register: interpret_adc_register_shifted_register(ins); break;
        case ARMInstructionId::add_immediate_thumb: interpret_add_immediate_thumb(ins); break;
        case ARMInstructionId::add_immediate_arm: interpret_add_immediate_arm(ins); break;
        case ARMInstructionId::add_register_thumb: interpret_add_register_thumb(ins); break;
        case ARMInstructionId::add_register_arm: interpret_add_register_arm(ins); break;
        case ARMInstructionId::add_register_shifted_register: interpret_add_register_shifted_register(ins); break;
        case ARMInstructionId::add_sp_plus_immediate: interpret_add_sp_plus_immediate(ins); break;
        case ARMInstructionId::add_sp_plus_register_thumb: interpret_add_sp_plus_register_thumb(ins); break;
        case ARMInstructionId::add_sp_plus_register_arm: interpret_add_sp_plus_register_arm(ins); break;
        case ARMInstructionId::adr: interpret_adr(ins); break;
        case ARMInstructionId::and_immediate: interpret_and_immediate(ins); break;
        case ARMInstructionId::and_register: interpret_and_register(ins); break;
        case ARMInstructionId::and_register_shifted_register: interpret_and_register_shifted_register(ins); break;
        case ARMInstructionId::asr_immediate: interpret_asr_immediate(ins); break;
        case ARMInstructionId::asr_register: interpret_asr_register(ins); break;
        case ARMInstructionId::b: interpret_b(ins); break;
        case ARMInstructionId::bfc: interpret_bfc(ins); break;
        case ARMInstructionId::bfi: interpret_bfi(ins); break;
        case ARMInstructionId::bic_immediate: interpret_bic_immediate(ins); break;
        case ARMInstructionId::bic_register: interpret_bic_register(ins); break;
        case ARMInstructionId::bic_register_shifted_register: interpret_bic_register_shifted_register(ins); break;
        case ARMInstructionId::bkpt: interpret_bkpt(ins); break;
        case ARMInstructionId::bl_blx_immediate: interpret_bl_blx_immediate(ins); break;
        case ARMInstructionId::blx_register: interpret_blx_register(ins); break;
        case ARMInstructionId::bx: interpret_bx(ins); break;
        case ARMInstructionId::bxj: interpret_bxj(ins); break;
        case ARMInstructionId::cbnz_cbz: interpret_cbnz_cbz(ins); break;
        case ARMInstructionId::cdp_cdp2: interpret_cdp_cdp2(ins); break;
        case ARMInstructionId::clrex: interpret_clrex(ins); break;
        case ARMInstructionId::clz: interpret_clz(ins); break;
        case ARMInstructionId::cmn_immediate: interpret_cmn_immediate(ins); break;
        case ARMInstructionId::cmn_register: interpret_cmn_register(ins); break;
        case ARMInstructionId::cmn_register_shifted_register: interpret_cmn_register_shifted_register(ins); break;
        case ARMInstructionId::cmp_immediate: interpret_cmp_immediate(ins); break;
        case ARMInstructionId::cmp_register: interpret_cmp_register(ins); break;
        case ARMInstructionId::cmp_register_shifted_register: interpret_cmp_register_shifted_register(ins); break;
        case ARMInstructionId::cps_thumb: interpret_cps_thumb(ins); break;
        case ARMInstructionId::cps_arm: interpret_cps_arm(ins); break;
        case ARMInstructionId::dbg: interpret_dbg(ins); break;
        case ARMInstructionId::dmb: interpret_dmb(ins); break;
        case ARMInstructionId::dsb: interpret_dsb(ins); break;
        case ARMInstructionId::eor_immediate: interpret_eor_immediate(ins); break;
        case ARMInstructionId::eor_register: interpret_eor_register(ins); break;
        case ARMInstructionId::eor_register_shifted_register: interpret_eor_register_shifted_register(ins); break;
        case ARMInstructionId::eret: interpret_eret(ins); break;
        case ARMInstructionId::hvc: interpret_hvc(ins); break;
        case ARMInstructionId::isb: interpret_isb(ins); break;
        case ARMInstructionId::it: interpret_it(ins); break;
        case ARMInstructionId::ldc_ldc2_immediate: interpret_ldc_ldc2_immediate(ins); break;
        case ARMInstructionId::ldc_ldc2_literal: interpret_ldc_ldc2_literal(ins); break;
        case ARMInstructionId::ldm_ldmia_ldmfd_thumb: interpret_ldm_ldmia_ldmfd_thumb(ins); break;
        case ARMInstructionId::ldm_ldmia_ldmfd_arm: interpret_ldm_ldmia_ldmfd_arm(ins); break;
        case ARMInstructionId::ldmda_ldmfa: interpret_ldmda_ldmfa(ins); break;
        case ARMInstructionId::ldmdb_ldmea: interpret_ldmdb_ldmea(ins); break;
        case ARMInstructionId::ldmib_ldmed: interpret_ldmib_ldmed(ins); break;
        case ARMInstructionId::ldr_immediate_thumb: interpret_ldr_immediate_thumb(ins); break;
        case ARMInstructionId::ldr_immediate_arm: interpret_ldr_immediate_arm(ins); break;
        case ARMInstructionId::ldr_literal: interpret_ldr_literal(ins); break;
        case ARMInstructionId::ldr_register_thumb: interpret_ldr_register_thumb(ins); break;
        case ARMInstructionId::ldr_register_arm: interpret_ldr_register_arm(ins); break;
        case ARMInstructionId::ldrb_immediate_thumb: interpret_ldrb_immediate_thumb(ins); break;
        case ARMInstructionId::ldrb_immediate_arm: interpret_ldrb_immediate_arm(ins); break;
        case ARMInstructionId::ldrb_literal: interpret_ldrb_literal(ins); break;
        case ARMInstructionId::ldrb_register: interpret_ldrb_register(ins); break;
        case ARMInstructionId::ldrbt: interpret_ldrbt(ins); break;
        case ARMInstructionId::ldrd_immediate: interpret_ldrd_immediate(ins); break;
        case ARMInstructionId::ldrd_literal: interpret_ldrd_literal(ins); break;
        case ARMInstructionId::ldrd_register: interpret_ldrd_register(ins); break;
        case ARMInstructionId::ldrex: interpret_ldrex(ins); break;
        case ARMInstructionId::ldrexb: interpret_ldrexb(ins); break;
        case ARMInstructionId::ldrexd: interpret_ldrexd(ins); break;
        case ARMInstructionId::ldrexh: interpret_ldrexh(ins); break;
        case ARMInstructionId::ldrh_immediate_thumb: interpret_ldrh_immediate_thumb(ins); break;
        case ARMInstructionId::ldrh_immediate_arm: interpret_ldrh_immediate_arm(ins); break;
        case ARMInstructionId::ldrh_literal: interpret_ldrh_literal(ins); break;
        case ARMInstructionId::ldrh_register: interpret_ldrh_register(ins); break;
        case ARMInstructionId::ldrht: interpret_ldrht(ins); break;
        case ARMInstructionId::ldrsb_immediate: interpret_ldrsb_immediate(ins); break;
        case ARMInstructionId::ldrsb_literal: interpret_ldrsb_literal(ins); break;
        case ARMInstructionId::ldrsb_register: interpret_ldrsb_register(ins); break;
        case ARMInstructionId::ldrsbt: interpret_ldrsbt(ins); break;
        case ARMInstructionId::ldrsh_immediate: interpret_ldrsh_immediate(ins); break;
        case ARMInstructionId::ldrsh_literal: interpret_ldrsh_literal(ins); break;
        case ARMInstructionId::ldrsh_register: interpret_ldrsh_register(ins); break;
        case ARMInstructionId::ldrsht: interpret_ldrsht(ins); break;
        case ARMInstructionId::ldrt: interpret_ldrt(ins); break;
        case ARMInstructionId::lsl_immediate: interpret_lsl_immediate(ins); break;
        case ARMInstructionId::lsl_register: interpret_lsl_register(ins); break;
        case ARMInstructionId::lsr_immediate: interpret_lsr_immediate(ins); break;
        case ARMInstructionId::lsr_register: interpret_lsr_register(ins); break;
        case ARMInstructionId::mcr_mcr2: interpret_mcr_mcr2(ins); break;
        case ARMInstructionId::mcrr_mcrr2: interpret_mcrr_mcrr2(ins); break;
        case ARMInstructionId::mla: interpret_mla(ins); break;
        case ARMInstructionId::mls: interpret_mls(ins); break;
        case ARMInstructionId::mov_immediate: interpret_mov_immediate(ins); break;
        case ARMInstructionId::mov_register_thumb: interpret_mov_register_thumb(ins); break;
        case ARMInstructionId::mov_register_arm: interpret_mov_register_arm(ins); break;
        case ARMInstructionId::movt: interpret_movt(ins); break;
        case ARMInstructionId::mrc_mrc2: interpret_mrc_mrc2(ins); break;
        case ARMInstructionId::mrrc_mrrc2: interpret_mrrc_mrrc2(ins); break;
        case ARMInstructionId::mrs: interpret_mrs(ins); break;
        case ARMInstructionId::mrs_banked_register: interpret_mrs_banked_register(ins); break;
        case ARMInstructionId::msr_immediate: interpret_msr_immediate(ins); break;
        case ARMInstructionId::msr_register: interpret_msr_register(ins); break;
        case ARMInstructionId::mul: interpret_mul(ins); break;
        case ARMInstructionId::mvn_immediate: interpret_mvn_immediate(ins); break;
        case ARMInstructionId::mvn_register: interpret_mvn_register(ins); break;
        case ARMInstructionId::mvn_register_shifted_register: interpret_mvn_register_shifted_register(ins); break;
        case ARMInstructionId::nop: interpret_nop(ins); break;
        case ARMInstructionId::orn_immediate: interpret_orn_immediate(ins); break;
        case ARMInstructionId::orn_register: interpret_orn_register(ins); break;
        case ARMInstructionId::orr_immediate: interpret_orr_immediate(ins); break;
        case ARMInstructionId::orr_register: interpret_orr_register(ins); break;
        case ARMInstructionId::orr_register_shifted_register: interpret_orr_register_shifted_register(ins); break;
        case ARMInstructionId::pkh: interpret_pkh(ins); break;
        case ARMInstructionId::pld_pldw_immediate: interpret_pld_pldw_immediate(ins); break;
        case ARMInstructionId::pld_literal: interpret_pld_literal(ins); break;
        case ARMInstructionId::pld_pldw_register: interpret_pld_pldw_register(ins); break;
        case ARMInstructionId::pli_immediate_literal: interpret_pli_immediate_literal(ins); break;
        case ARMInstructionId::pli_register: interpret_pli_register(ins); break;
        case ARMInstructionId::pop_thumb: interpret_pop_thumb(ins); break;
        case ARMInstructionId::pop_arm: interpret_pop_arm(ins); break;
        case ARMInstructionId::push: interpret_push(ins); break;
        case ARMInstructionId::qadd: interpret_qadd(ins); break;
        case ARMInstructionId::qadd16: interpret_qadd16(ins); break;
        case ARMInstructionId::qadd8: interpret_qadd8(ins); break;
        case ARMInstructionId::qasx: interpret_qasx(ins); break;
        case ARMInstructionId::qdadd: interpret_qdadd(ins); break;
        case ARMInstructionId::qdsub: interpret_qdsub(ins); break;
        case ARMInstructionId::qsax: interpret_qsax(ins); break;
        case ARMInstructionId::qsub: interpret_qsub(ins); break;
        case ARMInstructionId::qsub16: interpret_qsub16(ins); break;
        case ARMInstructionId::qsub8: interpret_qsub8(ins); break;
        case ARMInstructionId::rbit: interpret_rbit(ins); break;
        case ARMInstructionId::rev: interpret_rev(ins); break;
        case ARMInstructionId::rev16: interpret_rev16(ins); break;
        case ARMInstructionId::revsh: interpret_revsh(ins); break;
        case ARMInstructionId::rfe: interpret_rfe(ins); break;
        case ARMInstructionId::ror_immediate: interpret_ror_immediate(ins); break;
        case ARMInstructionId::ror_register: interpret_ror_register(ins); break;
        case ARMInstructionId::rrx: interpret_rrx(ins); break;
        case ARMInstructionId::rsb_immediate: interpret_rsb_immediate(ins); break;
        case ARMInstructionId::rsb_register: interpret_rsb_register(ins); break;
        case ARMInstructionId::rsb_register_shifted_register: interpret_rsb_register_shifted_register(ins); break;
        case ARMInstructionId::rsc_immediate: interpret_rsc_immediate(ins); break;
        case ARMInstructionId::rsc_register: interpret_rsc_register(ins); break;
        case ARMInstructionId::rsc_register_shifted_register: interpret_rsc_register_shifted_register(ins); break;
        case ARMInstructionId::sadd16: interpret_sadd16(ins); break;
        case ARMInstructionId::sadd8: interpret_sadd8(ins); break;
        case ARMInstructionId::sasx: interpret_sasx(ins); break;
        case ARMInstructionId::sbc_immediate: interpret_sbc_immediate(ins); break;
        case ARMInstructionId::sbc_register: interpret_sbc_register(ins); break;
        case ARMInstructionId::sbc_register_shifted_register: interpret_sbc_register_shifted_register(ins); break;
        case ARMInstructionId::sbfx: interpret_sbfx(ins); break;
        case ARMInstructionId::sdiv: interpret_sdiv(ins); break;
        case ARMInstructionId::sel: interpret_sel(ins); break;
        case ARMInstructionId::setend: interpret_setend(ins); break;
        case ARMInstructionId::sev: interpret_sev(ins); break;
        case ARMInstructionId::shadd16: interpret_shadd16(ins); break;
        case ARMInstructionId::shadd8: interpret_shadd8(ins); break;
        case ARMInstructionId::shasx: interpret_shasx(ins); break;
        case ARMInstructionId::shsax: interpret_shsax(ins); break;
        case ARMInstructionId::shsub16: interpret_shsub16(ins); break;
        case ARMInstructionId::shsub8: interpret_shsub8(ins); break;
        case ARMInstructionId::smc_previously_smi: interpret_smc_previously_smi(ins); break;
        case ARMInstructionId::smlabb_smlabt_smlatb_smlatt: interpret_smlabb_smlabt_smlatb_smlatt(ins); break;
        case ARMInstructionId::smlad: interpret_smlad(ins); break;
        case ARMInstructionId::smlal: interpret_smlal(ins); break;
        case ARMInstructionId::smlalbb_smlalbt_smlaltb_smlaltt: interpret_smlalbb_smlalbt_smlaltb_smlaltt(ins); break;
        case ARMInstructionId::smlald: interpret_smlald(ins); break;
        case ARMInstructionId::smlawb_smlawt: interpret_smlawb_smlawt(ins); break;
        case ARMInstructionId::smlsd: interpret_smlsd(ins); break;
        case ARMInstructionId::smlsld: interpret_smlsld(ins); break;
        case ARMInstructionId::smmla: interpret_smmla(ins); break;
        case ARMInstructionId::smmls: interpret_smmls(ins); break;
        case ARMInstructionId::smmul: interpret_smmul(ins); break;
        case ARMInstructionId::smuad: interpret_smuad(ins); break;
        case ARMInstructionId::smulbb_smulbt_smultb_smultt: interpret_smulbb_smulbt_smultb_smultt(ins); break;
        case ARMInstructionId::smull: interpret_smull(ins); break;
        case ARMInstructionId::smulwb_smulwt: interpret_smulwb_smulwt(ins); break;
        case ARMInstructionId::smusd: interpret_smusd(ins); break;
        case ARMInstructionId::srs_thumb: interpret_srs_thumb(ins); break;
        case ARMInstructionId::srs_arm: interpret_srs_arm(ins); break;
        case ARMInstructionId::ssat: interpret_ssat(ins); break;
        case ARMInstructionId::ssat16: interpret_ssat16(ins); break;
        case ARMInstructionId::ssax: interpret_ssax(ins); break;
        case ARMInstructionId::ssub16: interpret_ssub16(ins); break;
        case ARMInstructionId::ssub8: interpret_ssub8(ins); break;
        case ARMInstructionId::stc_stc2: interpret_stc_stc2(ins); break;
        case ARMInstructionId::stm_stmia_stmea: interpret_stm_stmia_stmea(ins); break;
        case ARMInstructionId::stmda_stmed: interpret_stmda_stmed(ins); break;
        case ARMInstructionId::stmdb_stmfd: interpret_stmdb_stmfd(ins); break;
        case ARMInstructionId::stmib_stmfa: interpret_stmib_stmfa(ins); break;
        case ARMInstructionId::str_immediate_thumb: interpret_str_immediate_thumb(ins); break;
        case ARMInstructionId::str_immediate_arm: interpret_str_immediate_arm(ins); break;
        case ARMInstructionId::str_register: interpret_str_register(ins); break;
        case ARMInstructionId::strb_immediate_thumb: interpret_strb_immediate_thumb(ins); break;
        case ARMInstructionId::strb_immediate_arm: interpret_strb_immediate_arm(ins); break;
        case ARMInstructionId::strb_register: interpret_strb_register(ins); break;
        case ARMInstructionId::strbt: interpret_strbt(ins); break;
        case ARMInstructionId::strd_immediate: interpret_strd_immediate(ins); break;
        case ARMInstructionId::strd_register: interpret_strd_register(ins); break;
        case ARMInstructionId::strex: interpret_strex(ins); break;
        case ARMInstructionId::strexb: interpret_strexb(ins); break;
        case ARMInstructionId::strexd: interpret_strexd(ins); break;
        case ARMInstructionId::strexh: interpret_strexh(ins); break;
        case ARMInstructionId::strh_immediate_thumb: interpret_strh_immediate_thumb(ins); break;
        case ARMInstructionId::strh_immediate_arm: interpret_strh_immediate_arm(ins); break;
        case ARMInstructionId::strh_register: interpret_strh_register(ins); break;
        case ARMInstructionId::strht: interpret_strht(ins); break;
        case ARMInstructionId::strt: interpret_strt(ins); break;
        case ARMInstructionId::sub_immediate_thumb: interpret_sub_immediate_thumb(ins); break;
        case ARMInstructionId::sub_immediate_arm: interpret_sub_immediate_arm(ins); break;
        case ARMInstructionId::sub_register: interpret_sub_register(ins); break;
        case ARMInstructionId::sub_register_shifted_register: interpret_sub_register_shifted_register(ins); break;
        case ARMInstructionId::sub_sp_minus_immediate: interpret_sub_sp_minus_immediate(ins); break;
        case ARMInstructionId::sub_sp_minus_register: interpret_sub_sp_minus_register(ins); break;
        case ARMInstructionId::subs_pc_lr_thumb: interpret_subs_pc_lr_thumb(ins); break;
        case ARMInstructionId::subs_pc_lr_and_related_instructions_arm: interpret_subs_pc_lr_and_related_instructions_arm(ins); break;
        case ARMInstructionId::svc: interpret_svc(ins); break;
        case ARMInstructionId::swp_swpb: interpret_swp_swpb(ins); break;
        case ARMInstructionId::sxtab: interpret_sxtab(ins); break;
        case ARMInstructionId::sxtab16: interpret_sxtab16(ins); break;
        case ARMInstructionId::sxtah: interpret_sxtah(ins); break;
        case ARMInstructionId::sxtb: interpret_sxtb(ins); break;
        case ARMInstructionId::sxtb16: interpret_sxtb16(ins); break;
        case ARMInstructionId::sxth: interpret_sxth(ins); break;
        case ARMInstructionId::tbb: interpret_tbb(ins); break;
        case ARMInstructionId::tbh: interpret_tbh(ins); break;
        case ARMInstructionId::teq_immediate: interpret_teq_immediate(ins); break;
        case ARMInstructionId::teq_register: interpret_teq_register(ins); break;
        case ARMInstructionId::teq_register_shifted_register: interpret_teq_register_shifted_register(ins); break;
        case ARMInstructionId::tst_immediate: interpret_tst_immediate(ins); break;
        case ARMInstructionId::tst_register: interpret_tst_register(ins); break;
        case ARMInstructionId::tst_register_shifted_register: interpret_tst_register_shifted_register(ins); break;
        case ARMInstructionId::uadd16: interpret_uadd16(ins); break;
        case ARMInstructionId::uadd8: interpret_uadd8(ins); break;
        case ARMInstructionId::uasx: interpret_uasx(ins); break;
        case ARMInstructionId::ubfx: interpret_ubfx(ins); break;
        case ARMInstructionId::udf: interpret_udf(ins); break;
        case ARMInstructionId::udiv: interpret_udiv(ins); break;
        case ARMInstructionId::uhadd16: interpret_uhadd16(ins); break;
        case ARMInstructionId::uhadd8: interpret_uhadd8(ins); break;
        case ARMInstructionId::uhasx: interpret_uhasx(ins); break;
        case ARMInstructionId::uhsax: interpret_uhsax(ins); break;
        case ARMInstructionId::uhsub16: interpret_uhsub16(ins); break;
        case ARMInstructionId::uhsub8: interpret_uhsub8(ins); break;
        case ARMInstructionId::umaal: interpret_umaal(ins); break;
        case ARMInstructionId::umlal: interpret_umlal(ins); break;
        case ARMInstructionId::umull: interpret_umull(ins); break;
        case ARMInstructionId::uqadd16: interpret_uqadd16(ins); break;
        case ARMInstructionId::uqadd8: interpret_uqadd8(ins); break;
        case ARMInstructionId::uqasx: interpret_uqasx(ins); break;
        case ARMInstructionId::uqsax: interpret_uqsax(ins); break;
        case ARMInstructionId::uqsub16: interpret_uqsub16(ins); break;
        case ARMInstructionId::uqsub8: interpret_uqsub8(ins); break;
        case ARMInstructionId::usad8: interpret_usad8(ins); break;
        case ARMInstructionId::usada8: interpret_usada8(ins); break;
        case ARMInstructionId::usat: interpret_usat(ins); break;
        case ARMInstructionId::usat16: interpret_usat16(ins); break;
        case ARMInstructionId::usax: interpret_usax(ins); break;
        case ARMInstructionId::usub16: interpret_usub16(ins); break;
        case ARMInstructionId::usub8: interpret_usub8(ins); break;
        case ARMInstructionId::uxtab: interpret_uxtab(ins); break;
        case ARMInstructionId::uxtab16: interpret_uxtab16(ins); break;
        case ARMInstructionId::uxtah: interpret_uxtah(ins); break;
        case ARMInstructionId::uxtb: interpret_uxtb(ins); break;
        case ARMInstructionId::uxtb16: interpret_uxtb16(ins); break;
        case ARMInstructionId::uxth: interpret_uxth(ins); break;
        case ARMInstructionId::vaba_vabal: interpret_vaba_vabal(ins); break;
        case ARMInstructionId::vabd_vabdl_integer: interpret_vabd_vabdl_integer(ins); break;
        case ARMInstructionId::vabd_floating_point: interpret_vabd_floating_point(ins); break;
        case ARMInstructionId::vabs: interpret_vabs(ins); break;
        case ARMInstructionId::vacge_vacgt_vacle_vaclt: interpret_vacge_vacgt_vacle_vaclt(ins); break;
        case ARMInstructionId::vadd_integer: interpret_vadd_integer(ins); break;
        case ARMInstructionId::vadd_floating_point: interpret_vadd_floating_point(ins); break;
        case ARMInstructionId::vaddhn: interpret_vaddhn(ins); break;
        case ARMInstructionId::vaddl_vaddw: interpret_vaddl_vaddw(ins); break;
        case ARMInstructionId::vand_register: interpret_vand_register(ins); break;
        case ARMInstructionId::vbic_immediate: interpret_vbic_immediate(ins); break;
        case ARMInstructionId::vbic_register: interpret_vbic_register(ins); break;
        case ARMInstructionId::vbif_vbit_vbsl: interpret_vbif_vbit_vbsl(ins); break;
        case ARMInstructionId::vceq_register: interpret_vceq_register(ins); break;
        case ARMInstructionId::vceq_immediate_0: interpret_vceq_immediate_0(ins); break;
        case ARMInstructionId::vcge_register: interpret_vcge_register(ins); break;
        case ARMInstructionId::vcge_immediate_0: interpret_vcge_immediate_0(ins); break;
        case ARMInstructionId::vcgt_register: interpret_vcgt_register(ins); break;
        case ARMInstructionId::vcgt_immediate_0: interpret_vcgt_immediate_0(ins); break;
        case ARMInstructionId::vcle_immediate_0: interpret_vcle_immediate_0(ins); break;
        case ARMInstructionId::vcls: interpret_vcls(ins); break;
        case ARMInstructionId::vclt_immediate_0: interpret_vclt_immediate_0(ins); break;
        case ARMInstructionId::vclz: interpret_vclz(ins); break;
        case ARMInstructionId::vcmp_vcmpe: interpret_vcmp_vcmpe(ins); break;
        case ARMInstructionId::vcnt: interpret_vcnt(ins); break;
        case ARMInstructionId::vcvt_between_floating_point_and_integer_advancedsimd: interpret_vcvt_between_floating_point_and_integer_advancedsimd(ins); break;
        case ARMInstructionId::vcvt_vcvtr_between_floating_point_and_integer_floating_point: interpret_vcvt_vcvtr_between_floating_point_and_integer_floating_point(ins); break;
        case ARMInstructionId::vcvt_between_floating_point_and_fixed_point_advancedsimd: interpret_vcvt_between_floating_point_and_fixed_point_advancedsimd(ins); break;
        case ARMInstructionId::vcvt_between_floating_point_and_fixed_point_floating_point: interpret_vcvt_between_floating_point_and_fixed_point_floating_point(ins); break;
        case ARMInstructionId::vcvt_between_double_precision_and_single_precision: interpret_vcvt_between_double_precision_and_single_precision(ins); break;
        case ARMInstructionId::vcvt_between_half_precision_and_single_precision_advancedsimd: interpret_vcvt_between_half_precision_and_single_precision_advancedsimd(ins); break;
        case ARMInstructionId::vcvtb_vcvtt: interpret_vcvtb_vcvtt(ins); break;
        case ARMInstructionId::vdiv: interpret_vdiv(ins); break;
        case ARMInstructionId::vdup_scalar: interpret_vdup_scalar(ins); break;
        case ARMInstructionId::vdup_arm_core_register: interpret_vdup_arm_core_register(ins); break;
        case ARMInstructionId::veor: interpret_veor(ins); break;
        case ARMInstructionId::vext: interpret_vext(ins); break;
        case ARMInstructionId::vfma_vfms: interpret_vfma_vfms(ins); break;
        case ARMInstructionId::vfnma_vfnms: interpret_vfnma_vfnms(ins); break;
        case ARMInstructionId::vhadd_vhsub: interpret_vhadd_vhsub(ins); break;
        case ARMInstructionId::vld1_multiple_single_elements: interpret_vld1_multiple_single_elements(ins); break;
        case ARMInstructionId::vld1_single_element_to_one_lane: interpret_vld1_single_element_to_one_lane(ins); break;
        case ARMInstructionId::vld1_single_element_to_all_lanes: interpret_vld1_single_element_to_all_lanes(ins); break;
        case ARMInstructionId::vld2_multiple_2_element_structures: interpret_vld2_multiple_2_element_structures(ins); break;
        case ARMInstructionId::vld2_single_2_element_structure_to_one_lane: interpret_vld2_single_2_element_structure_to_one_lane(ins); break;
        case ARMInstructionId::vld2_single_2_element_structure_to_all_lanes: interpret_vld2_single_2_element_structure_to_all_lanes(ins); break;
        case ARMInstructionId::vld3_multiple_3_element_structures: interpret_vld3_multiple_3_element_structures(ins); break;
        case ARMInstructionId::vld3_single_3_element_structure_to_one_lane: interpret_vld3_single_3_element_structure_to_one_lane(ins); break;
        case ARMInstructionId::vld3_single_3_element_structure_to_all_lanes: interpret_vld3_single_3_element_structure_to_all_lanes(ins); break;
        case ARMInstructionId::vld4_multiple_4_element_structures: interpret_vld4_multiple_4_element_structures(ins); break;
        case ARMInstructionId::vld4_single_4_element_structure_to_one_lane: interpret_vld4_single_4_element_structure_to_one_lane(ins); break;
        case ARMInstructionId::vld4_single_4_element_structure_to_all_lanes: interpret_vld4_single_4_element_structure_to_all_lanes(ins); break;
        case ARMInstructionId::vldm: interpret_vldm(ins); break;
        case ARMInstructionId::vldr: interpret_vldr(ins); break;
        case ARMInstructionId::vmax_vmin_integer: interpret_vmax_vmin_integer(ins); break;
        case ARMInstructionId::vmax_vmin_floating_point: interpret_vmax_vmin_floating_point(ins); break;
        case ARMInstructionId::vmla_vmlal_vmls_vmlsl_integer: interpret_vmla_vmlal_vmls_vmlsl_integer(ins); break;
        case ARMInstructionId::vmla_vmls_floating_point: interpret_vmla_vmls_floating_point(ins); break;
        case ARMInstructionId::vmla_vmlal_vmls_vmlsl_by_scalar: interpret_vmla_vmlal_vmls_vmlsl_by_scalar(ins); break;
        case ARMInstructionId::vmov_immediate: interpret_vmov_immediate(ins); break;
        case ARMInstructionId::vmov_register: interpret_vmov_register(ins); break;
        case ARMInstructionId::vmov_arm_core_register_to_scalar: interpret_vmov_arm_core_register_to_scalar(ins); break;
        case ARMInstructionId::vmov_scalar_to_arm_core_register: interpret_vmov_scalar_to_arm_core_register(ins); break;
        case ARMInstructionId::vmov_between_arm_core_register_and_single_precision_register: interpret_vmov_between_arm_core_register_and_single_precision_register(ins); break;
        case ARMInstructionId::vmov_between_two_arm_core_registers_and_two_single_precision_registers: interpret_vmov_between_two_arm_core_registers_and_two_single_precision_registers(ins); break;
        case ARMInstructionId::vmov_between_two_arm_core_registers_and_a_doubleword_extension_register: interpret_vmov_between_two_arm_core_registers_and_a_doubleword_extension_register(ins); break;
        case ARMInstructionId::vmovl: interpret_vmovl(ins); break;
        case ARMInstructionId::vmovn: interpret_vmovn(ins); break;
        case ARMInstructionId::vmrs: interpret_vmrs(ins); break;
        case ARMInstructionId::vmsr: interpret_vmsr(ins); break;
        case ARMInstructionId::vmul_vmull_integer_and_polynomial: interpret_vmul_vmull_integer_and_polynomial(ins); break;
        case ARMInstructionId::vmul_floating_point: interpret_vmul_floating_point(ins); break;
        case ARMInstructionId::vmul_vmull_by_scalar: interpret_vmul_vmull_by_scalar(ins); break;
        case ARMInstructionId::vmvn_immediate: interpret_vmvn_immediate(ins); break;
        case ARMInstructionId::vmvn_register: interpret_vmvn_register(ins); break;
        case ARMInstructionId::vneg: interpret_vneg(ins); break;
        case ARMInstructionId::vnmla_vnmls_vnmul: interpret_vnmla_vnmls_vnmul(ins); break;
        case ARMInstructionId::vorn_register: interpret_vorn_register(ins); break;
        case ARMInstructionId::vorr_immediate: interpret_vorr_immediate(ins); break;
        case ARMInstructionId::vorr_register: interpret_vorr_register(ins); break;
        case ARMInstructionId::vpadal: interpret_vpadal(ins); break;
        case ARMInstructionId::vpadd_integer: interpret_vpadd_integer(ins); break;
        case ARMInstructionId::vpadd_floating_point: interpret_vpadd_floating_point(ins); break;
        case ARMInstructionId::vpaddl: interpret_vpaddl(ins); break;
        case ARMInstructionId::vpmax_vpmin_integer: interpret_vpmax_vpmin_integer(ins); break;
        case ARMInstructionId::vpmax_vpmin_floating_point: interpret_vpmax_vpmin_floating_point(ins); break;
        case ARMInstructionId::vpop: interpret_vpop(ins); break;
        case ARMInstructionId::vpush: interpret_vpush(ins); break;
        case ARMInstructionId::vqabs: interpret_vqabs(ins); break;
        case ARMInstructionId::vqadd: interpret_vqadd(ins); break;
        case ARMInstructionId::vqdmlal_vqdmlsl: interpret_vqdmlal_vqdmlsl(ins); break;
        case ARMInstructionId::vqdmulh: interpret_vqdmulh(ins); break;
        case ARMInstructionId::vqdmull: interpret_vqdmull(ins); break;
        case ARMInstructionId::vqmovn_vqmovun: interpret_vqmovn_vqmovun(ins); break;
        case ARMInstructionId::vqneg: interpret_vqneg(ins); break;
        case ARMInstructionId::vqrdmulh: interpret_vqrdmulh(ins); break;
        case ARMInstructionId::vqrshl: interpret_vqrshl(ins); break;
        case ARMInstructionId::vqrshrn_vqrshrun: interpret_vqrshrn_vqrshrun(ins); break;
        case ARMInstructionId::vqshl_register: interpret_vqshl_register(ins); break;
        case ARMInstructionId::vqshl_vqshlu_immediate: interpret_vqshl_vqshlu_immediate(ins); break;
        case ARMInstructionId::vqshrn_vqshrun: interpret_vqshrn_vqshrun(ins); break;
        case ARMInstructionId::vqsub: interpret_vqsub(ins); break;
        case ARMInstructionId::vraddhn: interpret_vraddhn(ins); break;
        case ARMInstructionId::vrecpe: interpret_vrecpe(ins); break;
        case ARMInstructionId::vrecps: interpret_vrecps(ins); break;
        case ARMInstructionId::vrev16_vrev32_vrev64: interpret_vrev16_vrev32_vrev64(ins); break;
        case ARMInstructionId::vrhadd: interpret_vrhadd(ins); break;
        case ARMInstructionId::vrshl: interpret_vrshl(ins); break;
        case ARMInstructionId::vrshr: interpret_vrshr(ins); break;
        case ARMInstructionId::vrshrn: interpret_vrshrn(ins); break;
        case ARMInstructionId::vrsqrte: interpret_vrsqrte(ins); break;
        case ARMInstructionId::vrsqrts: interpret_vrsqrts(ins); break;
        case ARMInstructionId::vrsra: interpret_vrsra(ins); break;
        case ARMInstructionId::vrsubhn: interpret_vrsubhn(ins); break;
        case ARMInstructionId::vshl_immediate: interpret_vshl_immediate(ins); break;
        case ARMInstructionId::vshl_register: interpret_vshl_register(ins); break;
        case ARMInstructionId::vshll: interpret_vshll(ins); break;
        case ARMInstructionId::vshr: interpret_vshr(ins); break;
        case ARMInstructionId::vshrn: interpret_vshrn(ins); break;
        case ARMInstructionId::vsli: interpret_vsli(ins); break;
        case ARMInstructionId::vsqrt: interpret_vsqrt(ins); break;
        case ARMInstructionId::vsra: interpret_vsra(ins); break;
        case ARMInstructionId::vsri: interpret_vsri(ins); break;
        case ARMInstructionId::vst1_multiple_single_elements: interpret_vst1_multiple_single_elements(ins); break;
        case ARMInstructionId::vst1_single_element_from_one_lane: interpret_vst1_single_element_from_one_lane(ins); break;
        case ARMInstructionId::vst2_multiple_2_element_structures: interpret_vst2_multiple_2_element_structures(ins); break;
        case ARMInstructionId::vst2_single_2_element_structure_from_one_lane: interpret_vst2_single_2_element_structure_from_one_lane(ins); break;
        case ARMInstructionId::vst3_multiple_3_element_structures: interpret_vst3_multiple_3_element_structures(ins); break;
        case ARMInstructionId::vst3_single_3_element_structure_from_one_lane: interpret_vst3_single_3_element_structure_from_one_lane(ins); break;
        case ARMInstructionId::vst4_multiple_4_element_structures: interpret_vst4_multiple_4_element_structures(ins); break;
        case ARMInstructionId::vst4_single_4_element_structure_from_one_lane: interpret_vst4_single_4_element_structure_from_one_lane(ins); break;
        case ARMInstructionId::vstm: interpret_vstm(ins); break;
        case ARMInstructionId::vstr: interpret_vstr(ins); break;
        case ARMInstructionId::vsub_integer: interpret_vsub_integer(ins); break;
        case ARMInstructionId::vsub_floating_point: interpret_vsub_floating_point(ins); break;
        case ARMInstructionId::vsubhn: interpret_vsubhn(ins); break;
        case ARMInstructionId::vsubl_vsubw: interpret_vsubl_vsubw(ins); break;
        case ARMInstructionId::vswp: interpret_vswp(ins); break;
        case ARMInstructionId::vtbl_vtbx: interpret_vtbl_vtbx(ins); break;
        case ARMInstructionId::vtrn: interpret_vtrn(ins); break;
        case ARMInstructionId::vtst: interpret_vtst(ins); break;
        case ARMInstructionId::vuzp: interpret_vuzp(ins); break;
        case ARMInstructionId::vzip: interpret_vzip(ins); break;
        case ARMInstructionId::wfe: interpret_wfe(ins); break;
        case ARMInstructionId::wfi: interpret_wfi(ins); break;
        case ARMInstructionId::yield: interpret_yield(ins); break;
        default: break;
    }
}

bool ARMInterpreter::interpret_adc_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), ins.imm32, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
        }
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_adc_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_adc_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_immediate_thumb(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), ins.imm32, 0);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_immediate_arm(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), ins.imm32, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_register_thumb(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_register_arm(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, 0);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_sp_plus_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(13), ins.imm32, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_sp_plus_register_thumb(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(13), shifted, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_add_sp_plus_register_arm(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(13), shifted, 0);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_adr(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ((ins.add) ? (Align(m_ctx.readRegularRegister(15), 4) + ins.imm32) : (Align(m_ctx.readRegularRegister(15), 4) - ins.imm32));
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_and_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) & ins.imm32);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_and_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & shifted);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_and_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & shifted);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_asr_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), SRType_ASR, ins.shift_n, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_asr_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.n), SRType_ASR, shift_n, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_b(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        BranchWritePC((m_ctx.readRegularRegister(15) + ins.imm32));
    }
    return true;
}

bool ARMInterpreter::interpret_bfc(const ARMInstruction &ins) {
    int tmp_val = 0;

    if (ConditionPassed()) {
        if ((ins.msbit >= ins.lsbit)) {
            tmp_val = m_ctx.readRegularRegister(ins.d);
            set_bits(tmp_val, ins.msbit, ins.lsbit, Replicate(0, ((ins.msbit - ins.lsbit) + 1)));
            m_ctx.writeRegularRegister(ins.d, tmp_val);
        } else {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_bfi(const ARMInstruction &ins) {
    int tmp = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        if ((ins.msbit >= ins.lsbit)) {
            tmp = (ins.msbit - ins.lsbit);
            tmp_val = m_ctx.readRegularRegister(ins.d);
            set_bits(tmp_val, ins.msbit, ins.lsbit, get_bits(m_ctx.readRegularRegister(ins.n), tmp, 0));
            m_ctx.writeRegularRegister(ins.d, tmp_val);
        } else {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_bic_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) & NOT(ins.imm32, 32));
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_bic_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & NOT(shifted, 32));
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_bic_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & NOT(shifted, 32));
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_bkpt(const ARMInstruction &ins) {
    EncodingSpecificOperations();
    BKPTInstrDebugEvent();
    return true;
}

bool ARMInterpreter::interpret_bl_blx_immediate(const ARMInstruction &ins) {
    int targetAddress = 0;

    if (ConditionPassed()) {
        if ((CurrentInstrSet() == InstrSet_ARM)) {
            m_ctx.writeRegularRegister(14, (m_ctx.readRegularRegister(15) - 4));
        } else {
            m_ctx.writeRegularRegister(14, Concatenate(get_bits(m_ctx.readRegularRegister(15), 31, 1), 1, 1));
        }
        if ((ins.targetInstrSet == InstrSet_ARM)) {
            targetAddress = (Align(m_ctx.readRegularRegister(15), 4) + ins.imm32);
        } else {
            targetAddress = (m_ctx.readRegularRegister(15) + ins.imm32);
        }
        SelectInstrSet(ins.targetInstrSet);
        BranchWritePC(targetAddress);
    }
    return true;
}

bool ARMInterpreter::interpret_blx_register(const ARMInstruction &ins) {
    int target = 0;
    int next_instr_addr = 0;

    if (ConditionPassed()) {
        target = m_ctx.readRegularRegister(ins.m);
        if ((CurrentInstrSet() == InstrSet_ARM)) {
            next_instr_addr = (m_ctx.readRegularRegister(15) - 4);
            m_ctx.writeRegularRegister(14, next_instr_addr);
        } else {
            next_instr_addr = (m_ctx.readRegularRegister(15) - 2);
            m_ctx.writeRegularRegister(14, Concatenate(get_bits(next_instr_addr, 31, 1), 1, 1));
        }
        BXWritePC(target);
    }
    return true;
}

bool ARMInterpreter::interpret_bx(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        BXWritePC(m_ctx.readRegularRegister(ins.m));
    }
    return true;
}

bool ARMInterpreter::interpret_bxj(const ARMInstruction &ins) {
    int HSRString = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        if ((((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp()) && (m_ctx.HSTR.TJDBX == 1))) {
            HSRString = Zeros(25);
            tmp_val = HSRString;
            set_bits(tmp_val, 3, 0, ins.m);
            HSRString = tmp_val;
            WriteHSR(10, HSRString);
            TakeHypTrapException();
        }
        if (((m_ctx.JMCR.JE == 0) || (CurrentInstrSet() == InstrSet_ThumbEE))) {
            BXWritePC(m_ctx.readRegularRegister(ins.m));
        } else {
            if (JazelleAcceptsExecution()) {
                SwitchToJazelleExecution();
            } else {
                return false;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_cbnz_cbz(const ARMInstruction &ins) {
    EncodingSpecificOperations();
    if ((ins.nonzero ^ IsZero(m_ctx.readRegularRegister(ins.n)))) {
        BranchWritePC((m_ctx.readRegularRegister(15) + ins.imm32));
    }
    return true;
}

bool ARMInterpreter::interpret_cdp_cdp2(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            Coproc_InternalOperation(ins.cp, ThisInstr());
        }
    }
    return true;
}

bool ARMInterpreter::interpret_clrex(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        ClearExclusiveLocal(ProcessorID());
    }
    return true;
}

bool ARMInterpreter::interpret_clz(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = CountLeadingZeroBits(m_ctx.readRegularRegister(ins.m));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_cmn_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), ins.imm32, 0);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cmn_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, 0);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cmn_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), shifted, 0);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cmp_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(ins.imm32, 32), 1);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cmp_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), 1);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cmp_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), 1);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
        m_ctx.APSR.V = overflow;
    }
    return true;
}

bool ARMInterpreter::interpret_cps_thumb(const ARMInstruction &ins) {
    int cpsr_val = 0;

    EncodingSpecificOperations();
    if (CurrentModeIsNotUser()) {
        cpsr_val = m_ctx.CPSR;
        if (ins.enable) {
            if (ins.affectA) {
                set_bit(cpsr_val, 8, 0);
            }
            if (ins.affectI) {
                set_bit(cpsr_val, 7, 0);
            }
            if (ins.affectF) {
                set_bit(cpsr_val, 6, 0);
            }
        }
        if (ins.disable) {
            if (ins.affectA) {
                set_bit(cpsr_val, 8, 1);
            }
            if (ins.affectI) {
                set_bit(cpsr_val, 7, 1);
            }
            if (ins.affectF) {
                set_bit(cpsr_val, 6, 1);
            }
        }
        if (ins.changemode) {
            set_bits(cpsr_val, 4, 0, ins.mode);
        }
        CPSRWriteByInstr(cpsr_val, 15, false);
        if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_cps_arm(const ARMInstruction &ins) {
    int cpsr_val = 0;

    EncodingSpecificOperations();
    if (CurrentModeIsNotUser()) {
        cpsr_val = m_ctx.CPSR;
        if (ins.enable) {
            if (ins.affectA) {
                set_bit(cpsr_val, 8, 0);
            }
            if (ins.affectI) {
                set_bit(cpsr_val, 7, 0);
            }
            if (ins.affectF) {
                set_bit(cpsr_val, 6, 0);
            }
        }
        if (ins.disable) {
            if (ins.affectA) {
                set_bit(cpsr_val, 8, 1);
            }
            if (ins.affectI) {
                set_bit(cpsr_val, 7, 1);
            }
            if (ins.affectF) {
                set_bit(cpsr_val, 6, 1);
            }
        }
        if (ins.changemode) {
            set_bits(cpsr_val, 4, 0, ins.mode);
        }
        CPSRWriteByInstr(cpsr_val, 15, false);
    }
    return true;
}

bool ARMInterpreter::interpret_dbg(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        Hint_Debug(ins.option);
    }
    return true;
}

bool ARMInterpreter::interpret_dmb(const ARMInstruction &ins) {
    int domain = 0;
    int types = 0;

    if (ConditionPassed()) {
        switch (ins.option) {
            case 2:
                domain = MBReqDomain_OuterShareable;
                types = MBReqTypes_Writes;
                break;
            
            case 3:
                domain = MBReqDomain_OuterShareable;
                types = MBReqTypes_All;
                break;
            
            case 6:
                domain = MBReqDomain_Nonshareable;
                types = MBReqTypes_Writes;
                break;
            
            case 7:
                domain = MBReqDomain_Nonshareable;
                types = MBReqTypes_All;
                break;
            
            case 10:
                domain = MBReqDomain_InnerShareable;
                types = MBReqTypes_Writes;
                break;
            
            case 11:
                domain = MBReqDomain_InnerShareable;
                types = MBReqTypes_All;
                break;
            
            case 14:
                domain = MBReqDomain_FullSystem;
                types = MBReqTypes_Writes;
                break;
            
            default:
                domain = MBReqDomain_FullSystem;
                types = MBReqTypes_All;
                break;
            
        }
        
        if (((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp())) {
            if ((m_ctx.HCR.BSU == 3)) {
                domain = MBReqDomain_FullSystem;
            }
            if (((m_ctx.HCR.BSU == 2) && (domain != MBReqDomain_FullSystem))) {
                domain = MBReqDomain_OuterShareable;
            }
            if (((m_ctx.HCR.BSU == 1) && (domain == MBReqDomain_Nonshareable))) {
                domain = MBReqDomain_InnerShareable;
            }
        }
        DataMemoryBarrier(domain, types);
    }
    return true;
}

bool ARMInterpreter::interpret_dsb(const ARMInstruction &ins) {
    int domain = 0;
    int types = 0;

    if (ConditionPassed()) {
        switch (ins.option) {
            case 2:
                domain = MBReqDomain_OuterShareable;
                types = MBReqTypes_Writes;
                break;
            
            case 3:
                domain = MBReqDomain_OuterShareable;
                types = MBReqTypes_All;
                break;
            
            case 6:
                domain = MBReqDomain_Nonshareable;
                types = MBReqTypes_Writes;
                break;
            
            case 7:
                domain = MBReqDomain_Nonshareable;
                types = MBReqTypes_All;
                break;
            
            case 10:
                domain = MBReqDomain_InnerShareable;
                types = MBReqTypes_Writes;
                break;
            
            case 11:
                domain = MBReqDomain_InnerShareable;
                types = MBReqTypes_All;
                break;
            
            case 14:
                domain = MBReqDomain_FullSystem;
                types = MBReqTypes_Writes;
                break;
            
            default:
                domain = MBReqDomain_FullSystem;
                types = MBReqTypes_All;
                break;
            
        }
        
        if (((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp())) {
            if ((m_ctx.HCR.BSU == 3)) {
                domain = MBReqDomain_FullSystem;
            }
            if (((m_ctx.HCR.BSU == 2) && (domain != MBReqDomain_FullSystem))) {
                domain = MBReqDomain_OuterShareable;
            }
            if (((m_ctx.HCR.BSU == 1) && (domain == MBReqDomain_Nonshareable))) {
                domain = MBReqDomain_InnerShareable;
            }
        }
        DataSynchronizationBarrier(domain, types);
    }
    return true;
}

bool ARMInterpreter::interpret_eor_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) ^ ins.imm32);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_eor_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) ^ shifted);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_eor_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) ^ shifted);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_eret(const ARMInstruction &ins) {
    int new_pc_value = 0;

    if (ConditionPassed()) {
        if (unlikely((CurrentModeIsUserOrSystem() || (CurrentInstrSet() == InstrSet_ThumbEE)))) {
            return false;
        } else {
            new_pc_value = ((CurrentModeIsHyp()) ? m_ctx.ELR_hyp : m_ctx.readRegularRegister(14));
            CPSRWriteByInstr(m_ctx.SPSR, 15, true);
            if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
                return false;
            } else {
                BranchWritePC(new_pc_value);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_hvc(const ARMInstruction &ins) {
    EncodingSpecificOperations();
    if (unlikely(((!HasVirtExt() || IsSecure()) || !CurrentModeIsNotUser()))) {
        return false;
    } else {
        if ((m_ctx.SCR.HCE == 0)) {
            if (unlikely(CurrentModeIsHyp())) {
                return false;
            } else {
                return false;
            }
        } else {
            CallHypervisor(ins.imm32);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_isb(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        InstructionSynchronizationBarrier();
    }
    return true;
}

bool ARMInterpreter::interpret_it(const ARMInstruction &ins) {
    int tmp_val = 0;

    EncodingSpecificOperations();
    tmp_val = m_ctx.ITSTATE.IT;
    set_bits(tmp_val, 7, 0, Concatenate(ins.firstcond, ins.mask, 32));
    m_ctx.ITSTATE.IT = tmp_val;
    return true;
}

bool ARMInterpreter::interpret_ldc_ldc2_immediate(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            NullCheckIfThumbEE(ins.n);
            offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
            address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
            do {
                Coproc_SendLoadedWord(m_ctx.read_MemA(address, 4), ins.cp, ThisInstr());
            } while (Coproc_DoneLoading(ins.cp, ThisInstr()));
            
            if (ins.wback) {
                m_ctx.writeRegularRegister(ins.n, offset_addr);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldc_ldc2_literal(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            NullCheckIfThumbEE(15);
            offset_addr = ((ins.add) ? (Align(m_ctx.readRegularRegister(15), 4) + ins.imm32) : (Align(m_ctx.readRegularRegister(15), 4) - ins.imm32));
            address = ((ins.index) ? offset_addr : Align(m_ctx.readRegularRegister(15), 4));
            do {
                Coproc_SendLoadedWord(m_ctx.read_MemA(address, 4), ins.cp, ThisInstr());
            } while (Coproc_DoneLoading(ins.cp, ThisInstr()));
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldm_ldmia_ldmfd_thumb(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            LoadWritePC(m_ctx.read_MemA(address, 4));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 0))) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + (4 * BitCount(ins.registers))));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 1))) {
            m_ctx.writeRegularRegister(ins.n, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldm_ldmia_ldmfd_arm(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            LoadWritePC(m_ctx.read_MemA(address, 4));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 0))) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + (4 * BitCount(ins.registers))));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 1))) {
            m_ctx.writeRegularRegister(ins.n, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldmda_ldmfa(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        address = ((m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))) + 4);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            LoadWritePC(m_ctx.read_MemA(address, 4));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 0))) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 1))) {
            m_ctx.writeRegularRegister(ins.n, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldmdb_ldmea(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers)));
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            LoadWritePC(m_ctx.read_MemA(address, 4));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 0))) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 1))) {
            m_ctx.writeRegularRegister(ins.n, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldmib_ldmed(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        address = (m_ctx.readRegularRegister(ins.n) + 4);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            LoadWritePC(m_ctx.read_MemA(address, 4));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 0))) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + (4 * BitCount(ins.registers))));
        }
        if ((ins.wback && (get_bit(ins.registers, ins.n) == 1))) {
            m_ctx.writeRegularRegister(ins.n, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldr_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 4);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((ins.t == 15)) {
            if ((get_bits(address, 1, 0) == 0)) {
                LoadWritePC(data);
            } else {
                return false;
            }
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldr_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 4);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((ins.t == 15)) {
            if ((get_bits(address, 1, 0) == 0)) {
                LoadWritePC(data);
            } else {
                return false;
            }
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            m_ctx.writeRegularRegister(ins.t, ROR(data, (8 * UInt(get_bits(address, 1, 0)))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldr_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        base = Align(m_ctx.readRegularRegister(15), 4);
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        data = m_ctx.read_MemU(address, 4);
        if ((ins.t == 15)) {
            if ((get_bits(address, 1, 0) == 0)) {
                LoadWritePC(data);
            } else {
                return false;
            }
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            if ((CurrentInstrSet() == InstrSet_ARM)) {
                m_ctx.writeRegularRegister(ins.t, ROR(data, (8 * UInt(get_bits(address, 1, 0)))));
            } else {
                m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldr_register_thumb(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = (m_ctx.readRegularRegister(ins.n) + offset);
        address = offset_addr;
        data = m_ctx.read_MemU(address, 4);
        if ((ins.t == 15)) {
            if ((get_bits(address, 1, 0) == 0)) {
                LoadWritePC(data);
            } else {
                return false;
            }
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldr_register_arm(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 4);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
            if ((ins.t == 15)) {
                if ((get_bits(address, 1, 0) == 0)) {
                    LoadWritePC(data);
                } else {
                    return false;
                }
            }
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            m_ctx.writeRegularRegister(ins.t, ROR(data, (8 * UInt(get_bits(address, 1, 0)))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrb_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemU(address, 1), 32));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrb_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemU(address, 1), 32));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrb_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        base = Align(m_ctx.readRegularRegister(15), 4);
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemU(address, 1), 32));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrb_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemU(address, 1), 32));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrbt(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemU_unpriv(address, 1), 32));
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrd_immediate(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;
    int tmp1 = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((HaveLPAE() && (get_bits(address, 2, 0) == 0))) {
            data = m_ctx.read_MemA(address, 8);
            if (BigEndian()) {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 63, 32));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 31, 0));
            } else {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 31, 0));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 63, 32));
            }
        } else {
            tmp1 = (address + 4);
            m_ctx.writeRegularRegister(ins.t, m_ctx.read_MemA(address, 4));
            m_ctx.writeRegularRegister(ins.t2, m_ctx.read_MemA(tmp1, 4));
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrd_literal(const ARMInstruction &ins) {
    int address = 0;
    int data = 0;
    int tmp1 = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        address = ((ins.add) ? (Align(m_ctx.readRegularRegister(15), 4) + ins.imm32) : (Align(m_ctx.readRegularRegister(15), 4) - ins.imm32));
        if ((HaveLPAE() && (get_bits(address, 2, 0) == 0))) {
            data = m_ctx.read_MemA(address, 8);
            if (BigEndian()) {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 63, 32));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 31, 0));
            } else {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 31, 0));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 63, 32));
            }
        } else {
            tmp1 = (address + 4);
            m_ctx.writeRegularRegister(ins.t, m_ctx.read_MemA(address, 4));
            m_ctx.writeRegularRegister(ins.t2, m_ctx.read_MemA(tmp1, 4));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrd_register(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;
    int tmp1 = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + m_ctx.readRegularRegister(ins.m)) : (m_ctx.readRegularRegister(ins.n) - m_ctx.readRegularRegister(ins.m)));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((HaveLPAE() && (get_bits(address, 2, 0) == 0))) {
            data = m_ctx.read_MemA(address, 8);
            if (BigEndian()) {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 63, 32));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 31, 0));
            } else {
                m_ctx.writeRegularRegister(ins.t, get_bits(data, 31, 0));
                m_ctx.writeRegularRegister(ins.t2, get_bits(data, 63, 32));
            }
        } else {
            tmp1 = (address + 4);
            m_ctx.writeRegularRegister(ins.t, m_ctx.read_MemA(address, 4));
            m_ctx.writeRegularRegister(ins.t2, m_ctx.read_MemA(tmp1, 4));
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrex(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = (m_ctx.readRegularRegister(ins.n) + ins.imm32);
        SetExclusiveMonitors(address, 4);
        m_ctx.writeRegularRegister(ins.t, m_ctx.read_MemA(address, 4));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrexb(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        SetExclusiveMonitors(address, 1);
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemA(address, 1), 32));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrexd(const ARMInstruction &ins) {
    int address = 0;
    int value = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        SetExclusiveMonitors(address, 8);
        value = m_ctx.read_MemA(address, 8);
        m_ctx.writeRegularRegister(ins.t, ((BigEndian()) ? get_bits(value, 63, 32) : get_bits(value, 31, 0)));
        m_ctx.writeRegularRegister(ins.t2, ((BigEndian()) ? get_bits(value, 31, 0) : get_bits(value, 63, 32)));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrexh(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        SetExclusiveMonitors(address, 2);
        m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.read_MemA(address, 2), 32));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrh_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 2);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrh_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 2);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrh_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        base = Align(m_ctx.readRegularRegister(15), 4);
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        data = m_ctx.read_MemU(address, 2);
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrh_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 2);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrht(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? m_ctx.readRegularRegister(ins.m) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        data = m_ctx.read_MemU_unpriv(address, 2);
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsb_immediate(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.writeRegularRegister(ins.t, SignExtend(m_ctx.read_MemU(address, 1), 8));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsb_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        base = Align(m_ctx.readRegularRegister(15), 4);
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        m_ctx.writeRegularRegister(ins.t, SignExtend(m_ctx.read_MemU(address, 1), 8));
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsb_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.writeRegularRegister(ins.t, SignExtend(m_ctx.read_MemU(address, 1), 8));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsbt(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? m_ctx.readRegularRegister(ins.m) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        m_ctx.writeRegularRegister(ins.t, SignExtend(m_ctx.read_MemU_unpriv(address, 1), 8));
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsh_immediate(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 2);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, SignExtend(data, 16));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsh_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(15);
        base = Align(m_ctx.readRegularRegister(15), 4);
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        data = m_ctx.read_MemU(address, 2);
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, SignExtend(data, 16));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsh_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        data = m_ctx.read_MemU(address, 2);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, SignExtend(data, 16));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrsht(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? m_ctx.readRegularRegister(ins.m) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        data = m_ctx.read_MemU_unpriv(address, 2);
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, SignExtend(data, 16));
        } else {
            m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ldrt(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        data = m_ctx.read_MemU_unpriv(address, 4);
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.writeRegularRegister(ins.t, data);
        } else {
            if ((CurrentInstrSet() == InstrSet_ARM)) {
                m_ctx.writeRegularRegister(ins.t, ROR(data, (8 * UInt(get_bits(address, 1, 0)))));
            } else {
                m_ctx.writeRegularRegister(ins.t, UNKNOWN_VALUE);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_lsl_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), SRType_LSL, ins.shift_n, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_lsl_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.n), SRType_LSL, shift_n, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_lsr_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), SRType_LSR, ins.shift_n, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_lsr_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.n), SRType_LSR, shift_n, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mcr_mcr2(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            Coproc_SendOneWord(m_ctx.readRegularRegister(ins.t), ins.cp, ThisInstr());
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mcrr_mcrr2(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            Coproc_SendTwoWords(m_ctx.readRegularRegister(ins.t2), m_ctx.readRegularRegister(ins.t), ins.cp, ThisInstr());
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mla(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int addend = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = SInt(m_ctx.readRegularRegister(ins.n), 32);
        operand2 = SInt(m_ctx.readRegularRegister(ins.m), 32);
        addend = SInt(m_ctx.readRegularRegister(ins.a), 32);
        result = ((operand1 * operand2) + addend);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mls(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int addend = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = SInt(m_ctx.readRegularRegister(ins.n), 32);
        operand2 = SInt(m_ctx.readRegularRegister(ins.m), 32);
        addend = SInt(m_ctx.readRegularRegister(ins.a), 32);
        result = (addend - (operand1 * operand2));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_mov_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ins.imm32;
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mov_register_thumb(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = m_ctx.readRegularRegister(ins.m);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mov_register_arm(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = m_ctx.readRegularRegister(ins.m);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_movt(const ARMInstruction &ins) {
    int tmp_val = 0;

    if (ConditionPassed()) {
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 31, 16, ins.imm32);
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_mrc_mrc2(const ARMInstruction &ins) {
    int value = 0;

    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            value = Coproc_GetOneWord(ins.cp, ThisInstr());
            if ((ins.t != 15)) {
                m_ctx.writeRegularRegister(ins.t, value);
            } else {
                m_ctx.APSR.N = get_bit(value, 31);
                m_ctx.APSR.Z = get_bit(value, 30);
                m_ctx.APSR.C = get_bit(value, 29);
                m_ctx.APSR.V = get_bit(value, 28);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mrrc_mrrc2(const ARMInstruction &ins) {
    int tmp0 = 0;
    int tmp1 = 0;

    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            std::tie(tmp0, tmp1) = Coproc_GetTwoWords(ins.cp, ThisInstr());
            m_ctx.writeRegularRegister(ins.t2, tmp0);
            m_ctx.writeRegularRegister(ins.t, tmp1);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mrs(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        m_ctx.writeRegularRegister(ins.d, m_ctx.APSR);
    }
    return true;
}

bool ARMInterpreter::interpret_mrs_banked_register(const ARMInstruction &ins) {
    int mode = 0;
    int m = 0;
    int targetmode = 0;

    if (ConditionPassed()) {
        if (unlikely(!CurrentModeIsNotUser())) {
            return false;
        } else {
            mode = m_ctx.CPSR.M;
            if (ins.read_spsr) {
                SPSRaccessValid(ins.SYSm, mode);
                switch (ins.SYSm) {
                    case 14:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_fiq);
                        break;
                    
                    case 16:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_irq);
                        break;
                    
                    case 18:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_svc);
                        break;
                    
                    case 20:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_abt);
                        break;
                    
                    case 22:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_und);
                        break;
                    
                    case 28:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_mon);
                        break;
                    
                    case 30:
                        m_ctx.writeRegularRegister(ins.d, m_ctx.SPSR_hyp);
                        break;
                    
                }
                
            } else {
                BankedRegisterAccessValid(ins.SYSm, mode);
                if ((get_bits(ins.SYSm, 4, 3) == 0)) {
                    m = (UInt(get_bits(ins.SYSm, 2, 0)) + 8);
                    m_ctx.writeRegularRegister(ins.d, m_ctx.readRmode(m, 16));
                }
                if ((get_bits(ins.SYSm, 4, 3) == 1)) {
                    m = (UInt(get_bits(ins.SYSm, 2, 0)) + 8);
                    m_ctx.writeRegularRegister(ins.d, m_ctx.readRmode(m, 17));
                }
                if ((get_bits(ins.SYSm, 4, 3) == 3)) {
                    if ((get_bit(ins.SYSm, 1) == 0)) {
                        m = (UInt(get_bit(ins.SYSm, 0)) + 13);
                        m_ctx.writeRegularRegister(ins.d, m_ctx.readRmode(m, 22));
                    } else {
                        if ((get_bit(ins.SYSm, 0) == 0)) {
                            m_ctx.writeRegularRegister(ins.d, m_ctx.readRmode(13, 26));
                        } else {
                            m_ctx.writeRegularRegister(ins.d, m_ctx.ELR_hyp);
                        }
                    }
                } else {
                    targetmode = 0;
                    targetmode = ((targetmode << 1) | 1);
                    targetmode = ((targetmode << 1) | (get_bit(ins.SYSm, 2) & get_bit(ins.SYSm, 1)));
                    targetmode = ((targetmode << 1) | (get_bit(ins.SYSm, 2) & ~get_bit(ins.SYSm, 1)));
                    targetmode = ((targetmode << 1) | 1);
                    targetmode = ((targetmode << 1) | (get_bit(ins.SYSm, 2) | get_bit(ins.SYSm, 1)));
                    if (unlikely((mode == targetmode))) {
                        return false;
                    } else {
                        m = (UInt(get_bit(ins.SYSm, 0)) + 13);
                        m_ctx.writeRegularRegister(ins.d, m_ctx.readRmode(m, targetmode));
                    }
                }
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_msr_immediate(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        if (ins.write_nzcvq) {
            m_ctx.APSR.N = get_bit(ins.imm32, 31);
            m_ctx.APSR.Z = get_bit(ins.imm32, 30);
            m_ctx.APSR.C = get_bit(ins.imm32, 29);
            m_ctx.APSR.V = get_bit(ins.imm32, 28);
            m_ctx.APSR.Q = get_bit(ins.imm32, 27);
        }
        if (ins.write_g) {
            m_ctx.APSR.GE = get_bits(ins.imm32, 19, 16);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_msr_register(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        if (ins.write_spsr) {
            SPSRWriteByInstr(m_ctx.readRegularRegister(ins.n), ins.mask);
        } else {
            CPSRWriteByInstr(m_ctx.readRegularRegister(ins.n), ins.mask, false);
        }
        if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mul(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = SInt(m_ctx.readRegularRegister(ins.n), 32);
        operand2 = SInt(m_ctx.readRegularRegister(ins.m), 32);
        result = (operand1 * operand2);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(get_bits(result, 31, 0));
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mvn_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = NOT(ins.imm32, 32);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mvn_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = NOT(shifted, 32);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_mvn_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = NOT(shifted, 32);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_nop(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        
    }
    return true;
}

bool ARMInterpreter::interpret_orn_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) | NOT(ins.imm32, 32));
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_orn_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) | NOT(shifted, 32));
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_orr_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) | ins.imm32);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_orr_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) | shifted);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_orr_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) | shifted);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_pkh(const ARMInstruction &ins) {
    int operand2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        operand2 = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, ((ins.tbform) ? get_bits(operand2, 15, 0) : get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)));
        set_bits(tmp_val, 31, 16, ((ins.tbform) ? get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) : get_bits(operand2, 31, 16)));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_pld_pldw_immediate(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        address = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        if (ins.is_pldw) {
            Hint_PreloadDataForWrite(address);
        } else {
            Hint_PreloadData(address);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_pld_literal(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        address = ((ins.add) ? (Align(m_ctx.readRegularRegister(15), 4) + ins.imm32) : (Align(m_ctx.readRegularRegister(15), 4) - ins.imm32));
        Hint_PreloadData(address);
    }
    return true;
}

bool ARMInterpreter::interpret_pld_pldw_register(const ARMInstruction &ins) {
    int offset = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        address = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        if (ins.is_pldw) {
            Hint_PreloadDataForWrite(address);
        } else {
            Hint_PreloadData(address);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_pli_immediate_literal(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;

    if (ConditionPassed()) {
        base = (((ins.n == 15)) ? Align(m_ctx.readRegularRegister(15), 4) : m_ctx.readRegularRegister(ins.n));
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        Hint_PreloadInstr(address);
    }
    return true;
}

bool ARMInterpreter::interpret_pli_register(const ARMInstruction &ins) {
    int offset = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        address = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        Hint_PreloadInstr(address);
    }
    return true;
}

bool ARMInterpreter::interpret_pop_thumb(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(13);
        address = m_ctx.readRegularRegister(13);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, ((ins.UnalignedAllowed) ? m_ctx.read_MemU(address, 4) : m_ctx.read_MemA(address, 4)));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            if (ins.UnalignedAllowed) {
                if ((get_bits(address, 1, 0) == 0)) {
                    LoadWritePC(m_ctx.read_MemU(address, 4));
                } else {
                    return false;
                }
            } else {
                LoadWritePC(m_ctx.read_MemA(address, 4));
            }
        }
        if ((get_bit(ins.registers, 13) == 0)) {
            m_ctx.writeRegularRegister(13, (m_ctx.readRegularRegister(13) + (4 * BitCount(ins.registers))));
        }
        if ((get_bit(ins.registers, 13) == 1)) {
            m_ctx.writeRegularRegister(13, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_pop_arm(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(13);
        address = m_ctx.readRegularRegister(13);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                m_ctx.writeRegularRegister(i, ((ins.UnalignedAllowed) ? m_ctx.read_MemU(address, 4) : m_ctx.read_MemA(address, 4)));
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            if (ins.UnalignedAllowed) {
                if ((get_bits(address, 1, 0) == 0)) {
                    LoadWritePC(m_ctx.read_MemU(address, 4));
                } else {
                    return false;
                }
            } else {
                LoadWritePC(m_ctx.read_MemA(address, 4));
            }
        }
        if ((get_bit(ins.registers, 13) == 0)) {
            m_ctx.writeRegularRegister(13, (m_ctx.readRegularRegister(13) + (4 * BitCount(ins.registers))));
        }
        if ((get_bit(ins.registers, 13) == 1)) {
            m_ctx.writeRegularRegister(13, UNKNOWN_VALUE);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_push(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(13);
        address = (m_ctx.readRegularRegister(13) - (4 * BitCount(ins.registers)));
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                if (((i == 13) && (i != LowestSetBit(ins.registers)))) {
                    m_ctx.write_MemA(address, 4, UNKNOWN_VALUE);
                } else {
                    if (ins.UnalignedAllowed) {
                        m_ctx.write_MemU(address, 4, m_ctx.readRegularRegister(i));
                    } else {
                        m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(i));
                    }
                }
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            if (ins.UnalignedAllowed) {
                m_ctx.write_MemU(address, 4, PCStoreValue());
            } else {
                m_ctx.write_MemA(address, 4, PCStoreValue());
            }
        }
        m_ctx.writeRegularRegister(13, (m_ctx.readRegularRegister(13) - (4 * BitCount(ins.registers))));
    }
    return true;
}

bool ARMInterpreter::interpret_qadd(const ARMInstruction &ins) {
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        std::tie(tmp_0, sat) = SignedSatQ((SInt(m_ctx.readRegularRegister(ins.m), 32) + SInt(m_ctx.readRegularRegister(ins.n), 32)), 32);
        m_ctx.writeRegularRegister(ins.d, tmp_0);
        if (sat) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_qadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignedSat(sum1, 16));
        set_bits(tmp_val, 31, 16, SignedSat(sum2, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_qadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        sum3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        sum4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, SignedSat(sum1, 8));
        set_bits(tmp_val, 15, 8, SignedSat(sum2, 8));
        set_bits(tmp_val, 23, 16, SignedSat(sum3, 8));
        set_bits(tmp_val, 31, 24, SignedSat(sum4, 8));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_qasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignedSat(diff, 16));
        set_bits(tmp_val, 31, 16, SignedSat(sum, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_qdadd(const ARMInstruction &ins) {
    int doubled = 0;
    int sat1 = 0;
    int tmp_0 = 0;
    int sat2 = 0;

    if (ConditionPassed()) {
        std::tie(doubled, sat1) = SignedSatQ((2 * SInt(m_ctx.readRegularRegister(ins.n), 32)), 32);
        std::tie(tmp_0, sat2) = SignedSatQ((SInt(m_ctx.readRegularRegister(ins.m), 32) + SInt(doubled, 32)), 32);
        m_ctx.writeRegularRegister(ins.d, tmp_0);
        if ((sat1 || sat2)) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_qdsub(const ARMInstruction &ins) {
    int doubled = 0;
    int sat1 = 0;
    int tmp_0 = 0;
    int sat2 = 0;

    if (ConditionPassed()) {
        std::tie(doubled, sat1) = SignedSatQ((2 * SInt(m_ctx.readRegularRegister(ins.n), 32)), 32);
        std::tie(tmp_0, sat2) = SignedSatQ((SInt(m_ctx.readRegularRegister(ins.m), 32) - SInt(doubled, 32)), 32);
        m_ctx.writeRegularRegister(ins.d, tmp_0);
        if ((sat1 || sat2)) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_qsax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignedSat(sum, 16));
        set_bits(tmp_val, 31, 16, SignedSat(diff, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_qsub(const ARMInstruction &ins) {
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        std::tie(tmp_0, sat) = SignedSatQ((SInt(m_ctx.readRegularRegister(ins.m), 32) - SInt(m_ctx.readRegularRegister(ins.n), 32)), 32);
        m_ctx.writeRegularRegister(ins.d, tmp_0);
        if (sat) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_qsub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignedSat(diff1, 16));
        set_bits(tmp_val, 31, 16, SignedSat(diff2, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_qsub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        diff3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        diff4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, SignedSat(diff1, 8));
        set_bits(tmp_val, 15, 8, SignedSat(diff2, 8));
        set_bits(tmp_val, 23, 16, SignedSat(diff3, 8));
        set_bits(tmp_val, 31, 24, SignedSat(diff4, 8));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_rbit(const ARMInstruction &ins) {
    int result = 0;
    int i = 0;

    if (ConditionPassed()) {
        result = 0;
        for (i = 0; i < 32; ++i) {
            result = ((result << 1) | get_bit(m_ctx.readRegularRegister(ins.m), i));
        }
        
        m_ctx.writeRegularRegister(ins.d, result);
    }
    return true;
}

bool ARMInterpreter::interpret_rev(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = 0;
        set_bits(result, 31, 24, get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        set_bits(result, 23, 16, get_bits(m_ctx.readRegularRegister(ins.m), 15, 8));
        set_bits(result, 15, 8, get_bits(m_ctx.readRegularRegister(ins.m), 23, 16));
        set_bits(result, 7, 0, get_bits(m_ctx.readRegularRegister(ins.m), 31, 24));
        m_ctx.writeRegularRegister(ins.d, result);
    }
    return true;
}

bool ARMInterpreter::interpret_rev16(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = 0;
        set_bits(result, 31, 24, get_bits(m_ctx.readRegularRegister(ins.m), 23, 16));
        set_bits(result, 23, 16, get_bits(m_ctx.readRegularRegister(ins.m), 31, 24));
        set_bits(result, 15, 8, get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        set_bits(result, 7, 0, get_bits(m_ctx.readRegularRegister(ins.m), 15, 8));
        m_ctx.writeRegularRegister(ins.d, result);
    }
    return true;
}

bool ARMInterpreter::interpret_revsh(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = 0;
        set_bits(result, 31, 8, SignExtend(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        set_bits(result, 7, 0, get_bits(m_ctx.readRegularRegister(ins.m), 15, 8));
        m_ctx.writeRegularRegister(ins.d, result);
    }
    return true;
}

bool ARMInterpreter::interpret_rfe(const ARMInstruction &ins) {
    int address = 0;
    int new_pc_value = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        if (unlikely((!CurrentModeIsNotUser() || (CurrentInstrSet() == InstrSet_ThumbEE)))) {
            return false;
        } else {
            address = ((ins.increment) ? m_ctx.readRegularRegister(ins.n) : (m_ctx.readRegularRegister(ins.n) - 8));
            if (ins.wordhigher) {
                address = (address + 4);
            }
            if (ins.wback) {
                m_ctx.writeRegularRegister(ins.n, ((ins.increment) ? (m_ctx.readRegularRegister(ins.n) + 8) : (m_ctx.readRegularRegister(ins.n) - 8)));
            }
            new_pc_value = m_ctx.read_MemA(address, 4);
            tmp = (address + 4);
            CPSRWriteByInstr(m_ctx.read_MemA(tmp, 4), 15, true);
            if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
                return false;
            } else {
                BranchWritePC(new_pc_value);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ror_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), SRType_ROR, ins.shift_n, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ror_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0));
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.n), SRType_ROR, shift_n, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rrx(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;

    if (ConditionPassed()) {
        std::tie(result, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), SRType_RRX, 1, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsb_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), ins.imm32, 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsb_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), shifted, 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsb_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), shifted, 1);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsc_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), ins.imm32, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsc_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), shifted, m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_rsc_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), shifted, m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum1, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(sum2, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((sum1 >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((sum2 >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_sadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        sum3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        sum4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(sum1, 7, 0));
        set_bits(tmp_val, 15, 8, get_bits(sum2, 7, 0));
        set_bits(tmp_val, 23, 16, get_bits(sum3, 7, 0));
        set_bits(tmp_val, 31, 24, get_bits(sum4, 7, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bit(tmp_val, 0, (((sum1 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 1, (((sum2 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 2, (((sum3 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 3, (((sum4 >= 0)) ? 1 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_sasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(sum, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((diff >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((sum >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_sbc_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(ins.imm32, 32), m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sbc_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), m_ctx.APSR.C);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sbc_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), m_ctx.APSR.C);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sbfx(const ARMInstruction &ins) {
    int msbit = 0;

    if (ConditionPassed()) {
        msbit = (ins.lsbit + ins.widthminus1);
        if ((msbit <= 31)) {
            m_ctx.writeRegularRegister(ins.d, SignExtend(get_bits(m_ctx.readRegularRegister(ins.n), msbit, ins.lsbit), 32));
        } else {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sdiv(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        if ((SInt(m_ctx.readRegularRegister(ins.m), 32) == 0)) {
            if (IntegerZeroDivideTrappingEnabled()) {
                GenerateIntegerZeroDivide();
            } else {
                result = 0;
            }
        } else {
            result = RoundTowardsZero((SInt(m_ctx.readRegularRegister(ins.n), 32) / SInt(m_ctx.readRegularRegister(ins.m), 32)));
        }
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_sel(const ARMInstruction &ins) {
    int tmp_val = 0;

    if (ConditionPassed()) {
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, (((get_bit(m_ctx.APSR.GE, 0) == 1)) ? get_bits(m_ctx.readRegularRegister(ins.n), 7, 0) : get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        set_bits(tmp_val, 15, 8, (((get_bit(m_ctx.APSR.GE, 1) == 1)) ? get_bits(m_ctx.readRegularRegister(ins.n), 15, 8) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        set_bits(tmp_val, 23, 16, (((get_bit(m_ctx.APSR.GE, 2) == 1)) ? get_bits(m_ctx.readRegularRegister(ins.n), 23, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        set_bits(tmp_val, 31, 24, (((get_bit(m_ctx.APSR.GE, 3) == 1)) ? get_bits(m_ctx.readRegularRegister(ins.n), 31, 24) : get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_setend(const ARMInstruction &ins) {
    EncodingSpecificOperations();
    m_ctx.CPSR.E = ((ins.set_bigend) ? 1 : 0);
    return true;
}

bool ARMInterpreter::interpret_sev(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        SendEvent();
    }
    return true;
}

bool ARMInterpreter::interpret_shadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum1, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(sum2, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_shadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        sum2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        sum3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        sum4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(sum1, 8, 1));
        set_bits(tmp_val, 15, 8, get_bits(sum2, 8, 1));
        set_bits(tmp_val, 23, 16, get_bits(sum3, 8, 1));
        set_bits(tmp_val, 31, 24, get_bits(sum4, 8, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_shasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(sum, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_shsax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(diff, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_shsub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff1, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(diff2, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_shsub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        diff3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        diff4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(diff1, 8, 1));
        set_bits(tmp_val, 15, 8, get_bits(diff2, 8, 1));
        set_bits(tmp_val, 23, 16, get_bits(diff3, 8, 1));
        set_bits(tmp_val, 31, 24, get_bits(diff4, 8, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_smc_previously_smi(const ARMInstruction &ins) {
    int HSRString = 0;

    if (ConditionPassed()) {
        if ((HaveSecurityExt() && CurrentModeIsNotUser())) {
            if ((((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp()) && (m_ctx.HCR.TSC == 1))) {
                HSRString = Zeros(25);
                WriteHSR(19, HSRString);
                TakeHypTrapException();
            } else {
                if ((m_ctx.SCR.SCD == 1)) {
                    if (unlikely(IsSecure())) {
                        return false;
                    } else {
                        return false;
                    }
                } else {
                    TakeSMCException();
                }
            }
        } else {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlabb_smlabt_smlatb_smlatt(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = ((ins.n_high) ? get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.n), 15, 0));
        operand2 = ((ins.m_high) ? get_bits(m_ctx.readRegularRegister(ins.m), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 0));
        result = ((SInt(operand1, 16) * SInt(operand2, 16)) + SInt(m_ctx.readRegularRegister(ins.a), 32));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if ((result != SInt(get_bits(result, 31, 0), 32))) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlad(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = ((product1 + product2) + SInt(m_ctx.readRegularRegister(ins.a), 32));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if ((result != SInt(get_bits(result, 31, 0), 32))) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlal(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ((SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(m_ctx.readRegularRegister(ins.m), 32)) + SInt(Concatenate(m_ctx.readRegularRegister(ins.dHi), m_ctx.readRegularRegister(ins.dLo), 32), 64));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 63);
            m_ctx.APSR.Z = IsZeroBit(get_bits(result, 63, 0));
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
                m_ctx.APSR.V = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlalbb_smlalbt_smlaltb_smlaltt(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = ((ins.n_high) ? get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.n), 15, 0));
        operand2 = ((ins.m_high) ? get_bits(m_ctx.readRegularRegister(ins.m), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 0));
        result = ((SInt(operand1, 16) * SInt(operand2, 16)) + SInt(Concatenate(m_ctx.readRegularRegister(ins.dHi), m_ctx.readRegularRegister(ins.dLo), 32), 64));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_smlald(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = ((product1 + product2) + SInt(Concatenate(m_ctx.readRegularRegister(ins.dHi), m_ctx.readRegularRegister(ins.dLo), 32), 64));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_smlawb_smlawt(const ARMInstruction &ins) {
    int operand2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_high) ? get_bits(m_ctx.readRegularRegister(ins.m), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 0));
        result = ((SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(operand2, 16)) + (SInt(m_ctx.readRegularRegister(ins.a), 32) << 16));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 47, 16));
        if (((result >> 16) != SInt(m_ctx.readRegularRegister(ins.d), 32))) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlsd(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = ((product1 - product2) + SInt(m_ctx.readRegularRegister(ins.a), 32));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if ((result != SInt(get_bits(result, 31, 0), 32))) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smlsld(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = ((product1 - product2) + SInt(Concatenate(m_ctx.readRegularRegister(ins.dHi), m_ctx.readRegularRegister(ins.dLo), 32), 64));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_smmla(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ((SInt(m_ctx.readRegularRegister(ins.a), 32) << 32) + (SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(m_ctx.readRegularRegister(ins.m), 32)));
        if (ins.round) {
            result = (result + 2147483648);
        }
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 63, 32));
    }
    return true;
}

bool ARMInterpreter::interpret_smmls(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ((SInt(m_ctx.readRegularRegister(ins.a), 32) << 32) - (SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(m_ctx.readRegularRegister(ins.m), 32)));
        if (ins.round) {
            result = (result + 2147483648);
        }
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 63, 32));
    }
    return true;
}

bool ARMInterpreter::interpret_smmul(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(m_ctx.readRegularRegister(ins.m), 32));
        if (ins.round) {
            result = (result + 2147483648);
        }
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 63, 32));
    }
    return true;
}

bool ARMInterpreter::interpret_smuad(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = (product1 + product2);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
        if ((result != SInt(get_bits(result, 31, 0), 32))) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smulbb_smulbt_smultb_smultt(const ARMInstruction &ins) {
    int operand1 = 0;
    int operand2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand1 = ((ins.n_high) ? get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.n), 15, 0));
        operand2 = ((ins.m_high) ? get_bits(m_ctx.readRegularRegister(ins.m), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 0));
        result = (SInt(operand1, 16) * SInt(operand2, 16));
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_smull(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(m_ctx.readRegularRegister(ins.m), 32));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 63);
            m_ctx.APSR.Z = IsZeroBit(get_bits(result, 63, 0));
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
                m_ctx.APSR.V = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_smulwb_smulwt(const ARMInstruction &ins) {
    int operand2 = 0;
    int product = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_high) ? get_bits(m_ctx.readRegularRegister(ins.m), 31, 16) : get_bits(m_ctx.readRegularRegister(ins.m), 15, 0));
        product = (SInt(m_ctx.readRegularRegister(ins.n), 32) * SInt(operand2, 16));
        m_ctx.writeRegularRegister(ins.d, get_bits(product, 47, 16));
    }
    return true;
}

bool ARMInterpreter::interpret_smusd(const ARMInstruction &ins) {
    int operand2 = 0;
    int product1 = 0;
    int product2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        operand2 = ((ins.m_swap) ? ROR(m_ctx.readRegularRegister(ins.m), 16) : m_ctx.readRegularRegister(ins.m));
        product1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) * SInt(get_bits(operand2, 15, 0), 16));
        product2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) * SInt(get_bits(operand2, 31, 16), 16));
        result = (product1 - product2);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_srs_thumb(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        if (unlikely(CurrentModeIsUserOrSystem())) {
            return false;
        }
        if (unlikely((ins.mode == 26))) {
            return false;
        } else {
            if (!IsSecure()) {
                if (unlikely(((ins.mode == 22) || ((ins.mode == 17) && (m_ctx.NSACR.RFR == 1))))) {
                    return false;
                }
            }
            base = m_ctx.readRmode(13, ins.mode);
            address = ((ins.increment) ? base : (base - 8));
            if (ins.wordhigher) {
                address = (address + 4);
            }
            tmp = (address + 4);
            m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(14));
            m_ctx.write_MemA(tmp, 4, m_ctx.SPSR);
            if (ins.wback) {
                m_ctx.writeRmode(13, ins.mode, ((ins.increment) ? (base + 8) : (base - 8)));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_srs_arm(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        if (unlikely(CurrentModeIsUserOrSystem())) {
            return false;
        }
        if (unlikely((ins.mode == 26))) {
            return false;
        } else {
            if (!IsSecure()) {
                if (unlikely(((ins.mode == 22) || ((ins.mode == 17) && (m_ctx.NSACR.RFR == 1))))) {
                    return false;
                }
            }
            base = m_ctx.readRmode(13, ins.mode);
            address = ((ins.increment) ? base : (base - 8));
            if (ins.wordhigher) {
                address = (address + 4);
            }
            tmp = (address + 4);
            m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(14));
            m_ctx.write_MemA(tmp, 4, m_ctx.SPSR);
            if (ins.wback) {
                m_ctx.writeRmode(13, ins.mode, ((ins.increment) ? (base + 8) : (base - 8)));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ssat(const ARMInstruction &ins) {
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        operand = Shift(m_ctx.readRegularRegister(ins.n), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, sat) = SignedSatQ(SInt(operand, 32), ins.saturate_to);
        m_ctx.writeRegularRegister(ins.d, SignExtend(result, ins.saturate_to));
        if (sat) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ssat16(const ARMInstruction &ins) {
    int result1 = 0;
    int sat1 = 0;
    int result2 = 0;
    int sat2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        std::tie(result1, sat1) = SignedSatQ(SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16), ins.saturate_to);
        std::tie(result2, sat2) = SignedSatQ(SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16), ins.saturate_to);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignExtend(result1, ins.saturate_to));
        set_bits(tmp_val, 31, 16, SignExtend(result2, ins.saturate_to));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        if ((sat1 || sat2)) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_ssax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) + SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        diff = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(diff, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((sum >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((diff >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_ssub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0), 16));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16), 16));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff1, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(diff2, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((diff1 >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((diff2 >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_ssub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0), 8));
        diff2 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8), 8));
        diff3 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16), 8));
        diff4 = (SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24), 8) - SInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24), 8));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(diff1, 7, 0));
        set_bits(tmp_val, 15, 8, get_bits(diff2, 7, 0));
        set_bits(tmp_val, 23, 16, get_bits(diff3, 7, 0));
        set_bits(tmp_val, 31, 24, get_bits(diff4, 7, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bit(tmp_val, 0, (((diff1 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 1, (((diff2 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 2, (((diff3 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 3, (((diff4 >= 0)) ? 1 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_stc_stc2(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (!Coproc_Accepted(ins.cp, ThisInstr())) {
            GenerateCoprocessorException();
        } else {
            NullCheckIfThumbEE(ins.n);
            offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
            address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
            do {
                m_ctx.write_MemA(address, 4, Coproc_GetWordToStore(ins.cp, ThisInstr()));
            } while (Coproc_DoneStoring(ins.cp, ThisInstr()));
            
            if (ins.wback) {
                m_ctx.writeRegularRegister(ins.n, offset_addr);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_stm_stmia_stmea(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                if ((((i == ins.n) && ins.wback) && (i != LowestSetBit(ins.registers)))) {
                    m_ctx.write_MemA(address, 4, UNKNOWN_VALUE);
                } else {
                    m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(i));
                }
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            m_ctx.write_MemA(address, 4, PCStoreValue());
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + (4 * BitCount(ins.registers))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_stmda_stmed(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        address = ((m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))) + 4);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                if ((((i == ins.n) && ins.wback) && (i != LowestSetBit(ins.registers)))) {
                    m_ctx.write_MemA(address, 4, UNKNOWN_VALUE);
                } else {
                    m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(i));
                }
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            m_ctx.write_MemA(address, 4, PCStoreValue());
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_stmdb_stmfd(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers)));
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                if ((((i == ins.n) && ins.wback) && (i != LowestSetBit(ins.registers)))) {
                    m_ctx.write_MemA(address, 4, UNKNOWN_VALUE);
                } else {
                    m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(i));
                }
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            m_ctx.write_MemA(address, 4, PCStoreValue());
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) - (4 * BitCount(ins.registers))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_stmib_stmfa(const ARMInstruction &ins) {
    int address = 0;
    int i = 0;

    if (ConditionPassed()) {
        address = (m_ctx.readRegularRegister(ins.n) + 4);
        for (i = 0; i < 14; ++i) {
            if ((get_bit(ins.registers, i) == 1)) {
                if ((((i == ins.n) && ins.wback) && (i != LowestSetBit(ins.registers)))) {
                    m_ctx.write_MemA(address, 4, UNKNOWN_VALUE);
                } else {
                    m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(i));
                }
                address = (address + 4);
            }
        }
        
        if ((get_bit(ins.registers, 15) == 1)) {
            m_ctx.write_MemA(address, 4, PCStoreValue());
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + (4 * BitCount(ins.registers))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_str_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((UnalignedSupport() || (get_bits(address, 1, 0) == 0))) {
            m_ctx.write_MemU(address, 4, m_ctx.readRegularRegister(ins.t));
        } else {
            m_ctx.write_MemU(address, 4, UNKNOWN_VALUE);
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_str_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.write_MemU(address, 4, (((ins.t == 15)) ? PCStoreValue() : m_ctx.readRegularRegister(ins.t)));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_str_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((ins.t == 15)) {
            data = PCStoreValue();
        } else {
            data = m_ctx.readRegularRegister(ins.t);
        }
        if (((UnalignedSupport() || (get_bits(address, 1, 0) == 0)) || (CurrentInstrSet() == InstrSet_ARM))) {
            m_ctx.write_MemU(address, 4, data);
        } else {
            m_ctx.write_MemU(address, 4, UNKNOWN_VALUE);
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strb_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.write_MemU(address, 1, get_bits(m_ctx.readRegularRegister(ins.t), 7, 0));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strb_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.write_MemU(address, 1, get_bits(m_ctx.readRegularRegister(ins.t), 7, 0));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strb_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        m_ctx.write_MemU(address, 1, get_bits(m_ctx.readRegularRegister(ins.t), 7, 0));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strbt(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        m_ctx.write_MemU_unpriv(address, 1, get_bits(m_ctx.readRegularRegister(ins.t), 7, 0));
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strd_immediate(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((HaveLPAE() && (get_bits(address, 2, 0) == 0))) {
            data = 0;
            if (BigEndian()) {
                set_bits(data, 63, 32, m_ctx.readRegularRegister(ins.t));
                set_bits(data, 31, 0, m_ctx.readRegularRegister(ins.t2));
            } else {
                set_bits(data, 31, 0, m_ctx.readRegularRegister(ins.t));
                set_bits(data, 63, 32, m_ctx.readRegularRegister(ins.t2));
            }
            m_ctx.write_MemA(address, 8, data);
        } else {
            tmp = (address + 4);
            m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(ins.t));
            m_ctx.write_MemA(tmp, 4, m_ctx.readRegularRegister(ins.t2));
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strd_register(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;
    int data = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + m_ctx.readRegularRegister(ins.m)) : (m_ctx.readRegularRegister(ins.n) - m_ctx.readRegularRegister(ins.m)));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((HaveLPAE() && (get_bits(address, 2, 0) == 0))) {
            data = 0;
            if (BigEndian()) {
                set_bits(data, 63, 32, m_ctx.readRegularRegister(ins.t));
                set_bits(data, 31, 0, m_ctx.readRegularRegister(ins.t2));
            } else {
                set_bits(data, 31, 0, m_ctx.readRegularRegister(ins.t));
                set_bits(data, 63, 32, m_ctx.readRegularRegister(ins.t2));
            }
            m_ctx.write_MemA(address, 8, data);
        } else {
            tmp = (address + 4);
            m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(ins.t));
            m_ctx.write_MemA(tmp, 4, m_ctx.readRegularRegister(ins.t2));
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strex(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = (m_ctx.readRegularRegister(ins.n) + ins.imm32);
        if (ExclusiveMonitorsPass(address, 4)) {
            m_ctx.write_MemA(address, 4, m_ctx.readRegularRegister(ins.t));
            m_ctx.writeRegularRegister(ins.d, 0);
        } else {
            m_ctx.writeRegularRegister(ins.d, 1);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strexb(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (ExclusiveMonitorsPass(address, 1)) {
            m_ctx.write_MemA(address, 1, m_ctx.readRegularRegister(ins.t));
            m_ctx.writeRegularRegister(ins.d, 0);
        } else {
            m_ctx.writeRegularRegister(ins.d, 1);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strexd(const ARMInstruction &ins) {
    int address = 0;
    int value = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        value = ((BigEndian()) ? Concatenate(m_ctx.readRegularRegister(ins.t), m_ctx.readRegularRegister(ins.t2), 32) : Concatenate(m_ctx.readRegularRegister(ins.t2), m_ctx.readRegularRegister(ins.t), 32));
        if (ExclusiveMonitorsPass(address, 8)) {
            m_ctx.write_MemA(address, 8, value);
            m_ctx.writeRegularRegister(ins.d, 0);
        } else {
            m_ctx.writeRegularRegister(ins.d, 1);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strexh(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (ExclusiveMonitorsPass(address, 2)) {
            m_ctx.write_MemA(address, 2, m_ctx.readRegularRegister(ins.t));
            m_ctx.writeRegularRegister(ins.d, 0);
        } else {
            m_ctx.writeRegularRegister(ins.d, 1);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strh_immediate_thumb(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.write_MemU(address, 2, get_bits(m_ctx.readRegularRegister(ins.t), 15, 0));
        } else {
            m_ctx.write_MemU(address, 2, UNKNOWN_VALUE);
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strh_immediate_arm(const ARMInstruction &ins) {
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.write_MemU(address, 2, get_bits(m_ctx.readRegularRegister(ins.t), 15, 0));
        } else {
            m_ctx.write_MemU(address, 2, UNKNOWN_VALUE);
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strh_register(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        offset = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.index) ? offset_addr : m_ctx.readRegularRegister(ins.n));
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.write_MemU(address, 2, get_bits(m_ctx.readRegularRegister(ins.t), 15, 0));
        } else {
            m_ctx.write_MemU(address, 2, UNKNOWN_VALUE);
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strht(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? m_ctx.readRegularRegister(ins.m) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        if ((UnalignedSupport() || (get_bit(address, 0) == 0))) {
            m_ctx.write_MemU_unpriv(address, 2, get_bits(m_ctx.readRegularRegister(ins.t), 15, 0));
        } else {
            m_ctx.write_MemU_unpriv(address, 2, UNKNOWN_VALUE);
        }
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_strt(const ARMInstruction &ins) {
    int offset = 0;
    int offset_addr = 0;
    int address = 0;
    int data = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        NullCheckIfThumbEE(ins.n);
        offset = ((ins.register_form) ? Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C) : ins.imm32);
        offset_addr = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + offset) : (m_ctx.readRegularRegister(ins.n) - offset));
        address = ((ins.postindex) ? m_ctx.readRegularRegister(ins.n) : offset_addr);
        if ((ins.t == 15)) {
            data = PCStoreValue();
        } else {
            data = m_ctx.readRegularRegister(ins.t);
        }
        if (((UnalignedSupport() || (get_bits(address, 1, 0) == 0)) || (CurrentInstrSet() == InstrSet_ARM))) {
            m_ctx.write_MemU_unpriv(address, 4, data);
        } else {
            m_ctx.write_MemU_unpriv(address, 4, UNKNOWN_VALUE);
        }
        if (ins.postindex) {
            m_ctx.writeRegularRegister(ins.n, offset_addr);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_immediate_thumb(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(ins.imm32, 32), 1);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_immediate_arm(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(ins.imm32, 32), 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(shifted, 32), 1);
        m_ctx.writeRegularRegister(ins.d, result);
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 31);
            m_ctx.APSR.Z = IsZeroBit(result);
            m_ctx.APSR.C = carry;
            m_ctx.APSR.V = overflow;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_sp_minus_immediate(const ARMInstruction &ins) {
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(13), NOT(ins.imm32, 32), 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sub_sp_minus_register(const ARMInstruction &ins) {
    int shifted = 0;
    int result = 0;
    int carry = 0;
    int overflow = 0;

    if (ConditionPassed()) {
        shifted = Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, carry, overflow) = AddWithCarry(m_ctx.readRegularRegister(13), NOT(shifted, 32), 1);
        if ((ins.d == 15)) {
            m_ctx.ALUWritePC(result);
        } else {
            m_ctx.writeRegularRegister(ins.d, result);
            if (ins.setflags) {
                m_ctx.APSR.N = get_bit(result, 31);
                m_ctx.APSR.Z = IsZeroBit(result);
                m_ctx.APSR.C = carry;
                m_ctx.APSR.V = overflow;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_subs_pc_lr_thumb(const ARMInstruction &ins) {
    int operand2 = 0;
    int result = 0;
    int ignored_1 = 0;
    int ignored_2 = 0;

    if (ConditionPassed()) {
        if (unlikely((CurrentModeIsUserOrSystem() || (CurrentInstrSet() == InstrSet_ThumbEE)))) {
            return false;
        } else {
            operand2 = ins.imm32;
            std::tie(result, ignored_1, ignored_2) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(operand2, 32), 1);
            CPSRWriteByInstr(m_ctx.SPSR, 15, true);
            if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
                return false;
            } else {
                BranchWritePC(result);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_subs_pc_lr_and_related_instructions_arm(const ARMInstruction &ins) {
    int operand2 = 0;
    int result = 0;
    int ignored_1 = 0;
    int ignored_2 = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        if (unlikely(CurrentModeIsUserOrSystem())) {
            return false;
        } else {
            operand2 = ((ins.register_form) ? Shift(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C) : ins.imm32);
            switch (ins.opcode_) {
                case 0:
                    result = (m_ctx.readRegularRegister(ins.n) & operand2);
                    break;
                
                case 1:
                    result = (m_ctx.readRegularRegister(ins.n) ^ operand2);
                    break;
                
                case 2:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(operand2, 32), 1);
                    break;
                
                case 3:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), operand2, 1);
                    break;
                
                case 4:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(m_ctx.readRegularRegister(ins.n), operand2, 0);
                    break;
                
                case 5:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(m_ctx.readRegularRegister(ins.n), operand2, m_ctx.APSR.C);
                    break;
                
                case 6:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(m_ctx.readRegularRegister(ins.n), NOT(operand2, 32), m_ctx.APSR.C);
                    break;
                
                case 7:
                    std::tie(result, ignored_1, ignored_2) = AddWithCarry(NOT(m_ctx.readRegularRegister(ins.n), 32), operand2, m_ctx.APSR.C);
                    break;
                
                case 12:
                    result = (m_ctx.readRegularRegister(ins.n) | operand2);
                    break;
                
                case 13:
                    result = operand2;
                    break;
                
                case 14:
                    result = (m_ctx.readRegularRegister(ins.n) & NOT(operand2, 32));
                    break;
                
                case 15:
                    result = NOT(operand2, 32);
                    break;
                
            }
            
            CPSRWriteByInstr(m_ctx.SPSR, 15, true);
            if (unlikely((((get_bits(m_ctx.CPSR, 4, 0) == 26) && (m_ctx.CPSR.J == 1)) && (m_ctx.CPSR.T == 1)))) {
                return false;
            } else {
                BranchWritePC(result);
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_svc(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CallSupervisor(get_bits(ins.imm32, 15, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_swp_swpb(const ARMInstruction &ins) {
    int val = 0;
    int data = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        if (unlikely(CurrentModeIsHyp())) {
            return false;
        }
        val = m_ctx.readRegularRegister(ins.n);
        data = m_ctx.read_MemA(val, ins.size);
        tmp = ((8 * ins.size) - 1);
        m_ctx.write_MemA(val, ins.size, get_bits(m_ctx.readRegularRegister(ins.t2), tmp, 0));
        if ((ins.size == 1)) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(data, 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, ROR(data, (8 * UInt(get_bits(m_ctx.readRegularRegister(ins.n), 1, 0)))));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_sxtab(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, (m_ctx.readRegularRegister(ins.n) + SignExtend(get_bits(rotated, 7, 0), 8)));
    }
    return true;
}

bool ARMInterpreter::interpret_sxtab16(const ARMInstruction &ins) {
    int rotated = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, (get_bits(m_ctx.readRegularRegister(ins.n), 15, 0) + SignExtend(get_bits(rotated, 7, 0), 8)));
        set_bits(tmp_val, 31, 16, (get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) + SignExtend(get_bits(rotated, 23, 16), 8)));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_sxtah(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, (m_ctx.readRegularRegister(ins.n) + SignExtend(get_bits(rotated, 15, 0), 16)));
    }
    return true;
}

bool ARMInterpreter::interpret_sxtb(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, SignExtend(get_bits(rotated, 7, 0), 8));
    }
    return true;
}

bool ARMInterpreter::interpret_sxtb16(const ARMInstruction &ins) {
    int rotated = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, SignExtend(get_bits(rotated, 7, 0), 8));
        set_bits(tmp_val, 31, 16, SignExtend(get_bits(rotated, 23, 16), 8));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_sxth(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, SignExtend(get_bits(rotated, 15, 0), 16));
    }
    return true;
}

bool ARMInterpreter::interpret_tbb(const ARMInstruction &ins) {
    int tmp = 0;
    int halfwords = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        tmp = (m_ctx.readRegularRegister(ins.n) + m_ctx.readRegularRegister(ins.m));
        halfwords = UInt(m_ctx.read_MemU(tmp, 1));
        BranchWritePC((m_ctx.readRegularRegister(15) + (2 * halfwords)));
    }
    return true;
}

bool ARMInterpreter::interpret_tbh(const ARMInstruction &ins) {
    int tmp = 0;
    int halfwords = 0;

    if (ConditionPassed()) {
        NullCheckIfThumbEE(ins.n);
        tmp = (m_ctx.readRegularRegister(ins.n) + LSL(m_ctx.readRegularRegister(ins.m), 1));
        halfwords = UInt(m_ctx.read_MemU(tmp, 2));
        BranchWritePC((m_ctx.readRegularRegister(15) + (2 * halfwords)));
    }
    return true;
}

bool ARMInterpreter::interpret_teq_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) ^ ins.imm32);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
    }
    return true;
}

bool ARMInterpreter::interpret_teq_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) ^ shifted);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
    }
    return true;
}

bool ARMInterpreter::interpret_teq_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) ^ shifted);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
    }
    return true;
}

bool ARMInterpreter::interpret_tst_immediate(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (m_ctx.readRegularRegister(ins.n) & ins.imm32);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = ExpandImm_C(ins.encoding, ins.imm12, m_ctx.APSR.C);
    }
    return true;
}

bool ARMInterpreter::interpret_tst_register(const ARMInstruction &ins) {
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & shifted);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
    }
    return true;
}

bool ARMInterpreter::interpret_tst_register_shifted_register(const ARMInstruction &ins) {
    int shift_n = 0;
    int shifted = 0;
    int carry = 0;
    int result = 0;

    if (ConditionPassed()) {
        shift_n = UInt(get_bits(m_ctx.readRegularRegister(ins.s), 7, 0));
        std::tie(shifted, carry) = Shift_C(m_ctx.readRegularRegister(ins.m), ins.shift_t, shift_n, m_ctx.APSR.C);
        result = (m_ctx.readRegularRegister(ins.n) & shifted);
        m_ctx.APSR.N = get_bit(result, 31);
        m_ctx.APSR.Z = IsZeroBit(result);
        m_ctx.APSR.C = carry;
    }
    return true;
}

bool ARMInterpreter::interpret_uadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum1, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(sum2, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((sum1 >= 65536)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((sum2 >= 65536)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_uadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        sum3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        sum4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(sum1, 7, 0));
        set_bits(tmp_val, 15, 8, get_bits(sum2, 7, 0));
        set_bits(tmp_val, 23, 16, get_bits(sum3, 7, 0));
        set_bits(tmp_val, 31, 24, get_bits(sum4, 7, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bit(tmp_val, 0, (((sum1 >= 256)) ? 1 : 0));
        set_bit(tmp_val, 1, (((sum2 >= 256)) ? 1 : 0));
        set_bit(tmp_val, 2, (((sum3 >= 256)) ? 1 : 0));
        set_bit(tmp_val, 3, (((sum4 >= 256)) ? 1 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_uasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(sum, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((diff >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((sum >= 65536)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_ubfx(const ARMInstruction &ins) {
    int msbit = 0;

    if (ConditionPassed()) {
        msbit = (ins.lsbit + ins.widthminus1);
        if ((msbit <= 31)) {
            m_ctx.writeRegularRegister(ins.d, ZeroExtend(get_bits(m_ctx.readRegularRegister(ins.n), msbit, ins.lsbit), 32));
        } else {
            return false;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_udf(const ARMInstruction &ins) {
    if (unlikely(ConditionPassed())) {
        return false;
    }
    return true;
}

bool ARMInterpreter::interpret_udiv(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        if ((UInt(m_ctx.readRegularRegister(ins.m)) == 0)) {
            if (IntegerZeroDivideTrappingEnabled()) {
                GenerateIntegerZeroDivide();
            } else {
                result = 0;
            }
        } else {
            result = RoundTowardsZero((UInt(m_ctx.readRegularRegister(ins.n)) / UInt(m_ctx.readRegularRegister(ins.m))));
        }
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_uhadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum1, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(sum2, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uhadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        sum3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        sum4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(sum1, 8, 1));
        set_bits(tmp_val, 15, 8, get_bits(sum2, 8, 1));
        set_bits(tmp_val, 23, 16, get_bits(sum3, 8, 1));
        set_bits(tmp_val, 31, 24, get_bits(sum4, 8, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uhasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(sum, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uhsax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(diff, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uhsub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff1, 16, 1));
        set_bits(tmp_val, 31, 16, get_bits(diff2, 16, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uhsub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        diff3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        diff4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(diff1, 8, 1));
        set_bits(tmp_val, 15, 8, get_bits(diff2, 8, 1));
        set_bits(tmp_val, 23, 16, get_bits(diff3, 8, 1));
        set_bits(tmp_val, 31, 24, get_bits(diff4, 8, 1));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_umaal(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (((UInt(m_ctx.readRegularRegister(ins.n)) * UInt(m_ctx.readRegularRegister(ins.m))) + UInt(m_ctx.readRegularRegister(ins.dHi))) + UInt(m_ctx.readRegularRegister(ins.dLo)));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_umlal(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = ((UInt(m_ctx.readRegularRegister(ins.n)) * UInt(m_ctx.readRegularRegister(ins.m))) + UInt(Concatenate(m_ctx.readRegularRegister(ins.dHi), m_ctx.readRegularRegister(ins.dLo), 32)));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 63);
            m_ctx.APSR.Z = IsZeroBit(get_bits(result, 63, 0));
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
                m_ctx.APSR.V = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_umull(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        result = (UInt(m_ctx.readRegularRegister(ins.n)) * UInt(m_ctx.readRegularRegister(ins.m)));
        m_ctx.writeRegularRegister(ins.dHi, get_bits(result, 63, 32));
        m_ctx.writeRegularRegister(ins.dLo, get_bits(result, 31, 0));
        if (ins.setflags) {
            m_ctx.APSR.N = get_bit(result, 63);
            m_ctx.APSR.Z = IsZeroBit(get_bits(result, 63, 0));
            if ((ArchVersion() == 4)) {
                m_ctx.APSR.C = UNKNOWN_VALUE;
                m_ctx.APSR.V = UNKNOWN_VALUE;
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_uqadd16(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, UnsignedSat(sum1, 16));
        set_bits(tmp_val, 31, 16, UnsignedSat(sum2, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uqadd8(const ARMInstruction &ins) {
    int sum1 = 0;
    int sum2 = 0;
    int sum3 = 0;
    int sum4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        sum2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        sum3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        sum4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, UnsignedSat(sum1, 8));
        set_bits(tmp_val, 15, 8, UnsignedSat(sum2, 8));
        set_bits(tmp_val, 23, 16, UnsignedSat(sum3, 8));
        set_bits(tmp_val, 31, 24, UnsignedSat(sum4, 8));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uqasx(const ARMInstruction &ins) {
    int diff = 0;
    int sum = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, UnsignedSat(diff, 16));
        set_bits(tmp_val, 31, 16, UnsignedSat(sum, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uqsax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, UnsignedSat(sum, 16));
        set_bits(tmp_val, 31, 16, UnsignedSat(diff, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uqsub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, UnsignedSat(diff1, 16));
        set_bits(tmp_val, 31, 16, UnsignedSat(diff2, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uqsub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        diff3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        diff4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, UnsignedSat(diff1, 8));
        set_bits(tmp_val, 15, 8, UnsignedSat(diff2, 8));
        set_bits(tmp_val, 23, 16, UnsignedSat(diff3, 8));
        set_bits(tmp_val, 31, 24, UnsignedSat(diff4, 8));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_usad8(const ARMInstruction &ins) {
    int absdiff1 = 0;
    int absdiff2 = 0;
    int absdiff3 = 0;
    int absdiff4 = 0;
    int result = 0;

    if (ConditionPassed()) {
        absdiff1 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0))));
        absdiff2 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8))));
        absdiff3 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16))));
        absdiff4 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24))));
        result = (((absdiff1 + absdiff2) + absdiff3) + absdiff4);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_usada8(const ARMInstruction &ins) {
    int absdiff1 = 0;
    int absdiff2 = 0;
    int absdiff3 = 0;
    int absdiff4 = 0;
    int result = 0;

    if (ConditionPassed()) {
        absdiff1 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0))));
        absdiff2 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8))));
        absdiff3 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16))));
        absdiff4 = Abs((UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24))));
        result = ((((UInt(m_ctx.readRegularRegister(ins.a)) + absdiff1) + absdiff2) + absdiff3) + absdiff4);
        m_ctx.writeRegularRegister(ins.d, get_bits(result, 31, 0));
    }
    return true;
}

bool ARMInterpreter::interpret_usat(const ARMInstruction &ins) {
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        operand = Shift(m_ctx.readRegularRegister(ins.n), ins.shift_t, ins.shift_n, m_ctx.APSR.C);
        std::tie(result, sat) = UnsignedSatQ(SInt(operand, 32), ins.saturate_to);
        m_ctx.writeRegularRegister(ins.d, ZeroExtend(result, 32));
        if (sat) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_usat16(const ARMInstruction &ins) {
    int result1 = 0;
    int sat1 = 0;
    int result2 = 0;
    int sat2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        std::tie(result1, sat1) = UnsignedSatQ(SInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0), 16), ins.saturate_to);
        std::tie(result2, sat2) = UnsignedSatQ(SInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16), 16), ins.saturate_to);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, ZeroExtend(result1, 16));
        set_bits(tmp_val, 31, 16, ZeroExtend(result2, 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        if ((sat1 || sat2)) {
            m_ctx.APSR.Q = 1;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_usax(const ARMInstruction &ins) {
    int sum = 0;
    int diff = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        sum = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) + UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        diff = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(sum, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(diff, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((sum >= 65536)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((diff >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_usub16(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 16)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, get_bits(diff1, 15, 0));
        set_bits(tmp_val, 31, 16, get_bits(diff2, 15, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bits(tmp_val, 1, 0, (((diff1 >= 0)) ? 3 : 0));
        set_bits(tmp_val, 3, 2, (((diff2 >= 0)) ? 3 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_usub8(const ARMInstruction &ins) {
    int diff1 = 0;
    int diff2 = 0;
    int diff3 = 0;
    int diff4 = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        diff1 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 7, 0)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 7, 0)));
        diff2 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 15, 8)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 15, 8)));
        diff3 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 23, 16)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 23, 16)));
        diff4 = (UInt(get_bits(m_ctx.readRegularRegister(ins.n), 31, 24)) - UInt(get_bits(m_ctx.readRegularRegister(ins.m), 31, 24)));
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 7, 0, get_bits(diff1, 7, 0));
        set_bits(tmp_val, 15, 8, get_bits(diff2, 7, 0));
        set_bits(tmp_val, 23, 16, get_bits(diff3, 7, 0));
        set_bits(tmp_val, 31, 24, get_bits(diff4, 7, 0));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
        tmp_val = m_ctx.APSR.GE;
        set_bit(tmp_val, 0, (((diff1 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 1, (((diff2 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 2, (((diff3 >= 0)) ? 1 : 0));
        set_bit(tmp_val, 3, (((diff4 >= 0)) ? 1 : 0));
        m_ctx.APSR.GE = tmp_val;
    }
    return true;
}

bool ARMInterpreter::interpret_uxtab(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, (m_ctx.readRegularRegister(ins.n) + ZeroExtend(get_bits(rotated, 7, 0), 32)));
    }
    return true;
}

bool ARMInterpreter::interpret_uxtab16(const ARMInstruction &ins) {
    int rotated = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, (get_bits(m_ctx.readRegularRegister(ins.n), 15, 0) + ZeroExtend(get_bits(rotated, 7, 0), 16)));
        set_bits(tmp_val, 31, 16, (get_bits(m_ctx.readRegularRegister(ins.n), 31, 16) + ZeroExtend(get_bits(rotated, 23, 16), 16)));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uxtah(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, (m_ctx.readRegularRegister(ins.n) + ZeroExtend(get_bits(rotated, 15, 0), 32)));
    }
    return true;
}

bool ARMInterpreter::interpret_uxtb(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, ZeroExtend(get_bits(rotated, 7, 0), 32));
    }
    return true;
}

bool ARMInterpreter::interpret_uxtb16(const ARMInstruction &ins) {
    int rotated = 0;
    int tmp_val = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        tmp_val = m_ctx.readRegularRegister(ins.d);
        set_bits(tmp_val, 15, 0, ZeroExtend(get_bits(rotated, 7, 0), 16));
        set_bits(tmp_val, 31, 16, ZeroExtend(get_bits(rotated, 23, 16), 16));
        m_ctx.writeRegularRegister(ins.d, tmp_val);
    }
    return true;
}

bool ARMInterpreter::interpret_uxth(const ARMInstruction &ins) {
    int rotated = 0;

    if (ConditionPassed()) {
        rotated = ROR(m_ctx.readRegularRegister(ins.m), ins.rotation);
        m_ctx.writeRegularRegister(ins.d, ZeroExtend(get_bits(rotated, 15, 0), 32));
    }
    return true;
}

bool ARMInterpreter::interpret_vaba_vabal(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int npr = 0;
    int mpr = 0;
    int val1 = 0;
    int val2 = 0;
    int op1 = 0;
    int op2 = 0;
    int absdiff = 0;
    int ds = 0;
    int esize2 = 0;
    int dr = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                npr = (ins.n + r);
                mpr = (ins.m + r);
                val1 = m_ctx.readDoubleRegister(npr);
                val2 = m_ctx.readDoubleRegister(mpr);
                op1 = m_ctx.readElement(val1, e, ins.esize);
                op2 = m_ctx.readElement(val2, e, ins.esize);
                absdiff = Abs((((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize)) - ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize))));
                if (ins.long_destination) {
                    ds = (ins.d >> 1);
                    esize2 = (2 * ins.esize);
                    val1 = m_ctx.readQuadRegister(ds);
                    val2 = m_ctx.readQuadRegister(ds);
                    m_ctx.writeElement(val1, e, esize2, (m_ctx.readElement(val2, e, esize2) + absdiff));
                } else {
                    dr = (ins.d + r);
                    val1 = m_ctx.readDoubleRegister(dr);
                    val2 = m_ctx.readDoubleRegister(dr);
                    m_ctx.writeElement(val1, e, ins.esize, (m_ctx.readElement(val2, e, ins.esize) + absdiff));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vabd_vabdl_integer(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int npr = 0;
    int mpr = 0;
    int val1 = 0;
    int val2 = 0;
    int op1 = 0;
    int op2 = 0;
    int absdiff = 0;
    int ds = 0;
    int esize2 = 0;
    int esize2_1 = 0;
    int dr = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                npr = (ins.n + r);
                mpr = (ins.m + r);
                val1 = m_ctx.readDoubleRegister(npr);
                val2 = m_ctx.readDoubleRegister(mpr);
                op1 = m_ctx.readElement(val1, e, ins.esize);
                op2 = m_ctx.readElement(val2, e, ins.esize);
                absdiff = Abs((((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize)) - ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize))));
                if (ins.long_destination) {
                    ds = (ins.d >> 1);
                    esize2 = (2 * ins.esize);
                    esize2_1 = (esize2 - 1);
                    val1 = m_ctx.readQuadRegister(ds);
                    m_ctx.writeElement(val1, e, esize2, get_bits(absdiff, esize2_1, 0));
                } else {
                    dr = (ins.d + r);
                    val1 = m_ctx.readDoubleRegister(dr);
                    esize2_1 = (ins.esize - 1);
                    m_ctx.writeElement(val1, e, ins.esize, get_bits(absdiff, esize2_1, 0));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vabd_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int npr = 0;
    int mpr = 0;
    int val1 = 0;
    int val2 = 0;
    int op1 = 0;
    int op2 = 0;
    int dpr = 0;
    int val3 = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                npr = (ins.n + r);
                mpr = (ins.m + r);
                val1 = m_ctx.readDoubleRegister(npr);
                val2 = m_ctx.readDoubleRegister(mpr);
                op1 = m_ctx.readElement(val1, e, ins.esize);
                op2 = m_ctx.readElement(val2, e, ins.esize);
                dpr = (ins.d + r);
                val3 = m_ctx.readDoubleRegister(dpr);
                m_ctx.writeElement(val3, e, ins.esize, FPAbs(FPSub(op1, op2, false)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vabs(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int dpr = 0;
    int mpr = 0;
    int esize_1 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    if (ins.floating_point) {
                        dpr = (ins.d + r);
                        mpr = (ins.m + r);
                        m_ctx.writeElement(m_ctx.readDoubleRegister(dpr), e, ins.esize, FPAbs(m_ctx.readElement(m_ctx.readDoubleRegister(mpr), e, ins.esize)));
                    } else {
                        dpr = (ins.d + r);
                        mpr = (ins.m + r);
                        esize_1 = (ins.esize - 1);
                        result = Abs(SInt(m_ctx.readElement(m_ctx.readDoubleRegister(mpr), e, ins.esize), ins.esize));
                        m_ctx.writeElement(m_ctx.readDoubleRegister(dpr), e, ins.esize, get_bits(result, esize_1, 0));
                    }
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FPAbs(m_ctx.readDoubleRegister(ins.m)));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPAbs(m_ctx.readSingleRegister(ins.m)));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vacge_vacgt_vacle_vaclt(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int npr = 0;
    int mpr = 0;
    int op1 = 0;
    int op2 = 0;
    int test_passed = 0;
    int dpr = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                npr = (ins.n + r);
                mpr = (ins.m + r);
                op1 = FPAbs(m_ctx.readElement(m_ctx.readDoubleRegister(npr), e, ins.esize));
                op2 = FPAbs(m_ctx.readElement(m_ctx.readDoubleRegister(mpr), e, ins.esize));
                if (ins.or_equal) {
                    test_passed = FPCompareGE(op1, op2, false);
                } else {
                    test_passed = FPCompareGT(op1, op2, false);
                }
                dpr = (ins.d + r);
                m_ctx.writeElement(m_ctx.readDoubleRegister(dpr), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vadd_integer(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int dpr = 0;
    int npr = 0;
    int mpr = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                dpr = (ins.d + r);
                npr = (ins.n + r);
                mpr = (ins.m + r);
                m_ctx.writeElement(m_ctx.readDoubleRegister(dpr), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister(npr), e, ins.esize) + m_ctx.readElement(m_ctx.readDoubleRegister(mpr), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vadd_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int dpr = 0;
    int npr = 0;
    int mpr = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    dpr = (ins.d + r);
                    npr = (ins.n + r);
                    mpr = (ins.m + r);
                    m_ctx.writeElement(m_ctx.readDoubleRegister(dpr), e, ins.esize, FPAdd(m_ctx.readElement(m_ctx.readDoubleRegister(npr), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister(mpr), e, ins.esize), false));
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FPAdd(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPAdd(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vaddhn(const ARMInstruction &ins) {
    int e = 0;
    int ns1 = 0;
    int ms1 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            ns1 = (ins.n >> 1);
            ms1 = (ins.m >> 1);
            result = (m_ctx.readElement(m_ctx.readQuadRegister(ns1), e, (2 * ins.esize)) + m_ctx.readElement(m_ctx.readQuadRegister(ms1), e, (2 * ins.esize)));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, ((2 * ins.esize) - 1), ins.esize));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vaddl_vaddw(const ARMInstruction &ins) {
    int e = 0;
    int ns1 = 0;
    int op1 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            if (ins.is_vaddw) {
                ns1 = (ins.n >> 1);
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readQuadRegister(ns1), e, (2 * ins.esize))) : SInt(m_ctx.readElement(m_ctx.readQuadRegister(ns1), e, (2 * ins.esize)), (2 * ins.esize)));
            } else {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize), ins.esize));
            }
            result = (op1 + ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize)));
            m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), get_bits(result, ((2 * ins.esize) - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vand_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.n + r)) & m_ctx.readDoubleRegister((ins.m + r))));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vbic_immediate(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.d + r)) & NOT(ins.imm64, 32)));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vbic_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.n + r)) & NOT(m_ctx.readDoubleRegister((ins.m + r)), 64)));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vbif_vbit_vbsl(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            switch (ins.operation) {
                case VBitOps_VBIF:
                    m_ctx.writeDoubleRegister((ins.d + r), ((m_ctx.readDoubleRegister((ins.d + r)) & m_ctx.readDoubleRegister((ins.m + r))) | (m_ctx.readDoubleRegister((ins.n + r)) & NOT(m_ctx.readDoubleRegister((ins.m + r)), 64))));
                    break;
                
                case VBitOps_VBIT:
                    m_ctx.writeDoubleRegister((ins.d + r), ((m_ctx.readDoubleRegister((ins.n + r)) & m_ctx.readDoubleRegister((ins.m + r))) | (m_ctx.readDoubleRegister((ins.d + r)) & NOT(m_ctx.readDoubleRegister((ins.m + r)), 64))));
                    break;
                
                case VBitOps_VBSL:
                    m_ctx.writeDoubleRegister((ins.d + r), ((m_ctx.readDoubleRegister((ins.n + r)) & m_ctx.readDoubleRegister((ins.d + r))) | (m_ctx.readDoubleRegister((ins.m + r)) & NOT(m_ctx.readDoubleRegister((ins.d + r)), 64))));
                    break;
                
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vceq_register(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                if (ins.int_operation) {
                    test_passed = (op1 == op2);
                } else {
                    test_passed = FPCompareEQ(op1, op2, false);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vceq_immediate_0(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    test_passed = FPCompareEQ(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), FPZero(0, ins.esize), false);
                } else {
                    test_passed = (m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize) == Zeros(ins.esize));
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcge_register(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                switch (ins.type) {
                    case VCGEtype_signed:
                        test_passed = (SInt(op1, ins.esize) >= SInt(op2, ins.esize));
                        break;
                    
                    case VCGEtype_unsigned:
                        test_passed = (UInt(op1) >= UInt(op2));
                        break;
                    
                    case VCGEtype_fp:
                        test_passed = FPCompareGE(op1, op2, false);
                        break;
                    
                }
                
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcge_immediate_0(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    test_passed = FPCompareGE(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), FPZero(0, ins.esize), false);
                } else {
                    test_passed = (SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize) >= 0);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcgt_register(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                switch (ins.type) {
                    case VCGTtype_signed:
                        test_passed = (SInt(op1, ins.esize) > SInt(op2, ins.esize));
                        break;
                    
                    case VCGTtype_unsigned:
                        test_passed = (UInt(op1) > UInt(op2));
                        break;
                    
                    case VCGTtype_fp:
                        test_passed = FPCompareGT(op1, op2, false);
                        break;
                    
                }
                
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcgt_immediate_0(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    test_passed = FPCompareGT(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), FPZero(0, ins.esize), false);
                } else {
                    test_passed = (SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize) > 0);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcle_immediate_0(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    test_passed = FPCompareGE(FPZero(0, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false);
                } else {
                    test_passed = (SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize) <= 0);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcls(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, CountLeadingSignBits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vclt_immediate_0(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int test_passed = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    test_passed = FPCompareGT(FPZero(0, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false);
                } else {
                    test_passed = (SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize) < 0);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((test_passed) ? Ones(ins.esize) : Zeros(ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vclz(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, CountLeadingZeroBits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcmp_vcmpe(const ARMInstruction &ins) {
    int op2 = 0;
    int tmp_N = 0;
    int tmp_Z = 0;
    int tmp_C = 0;
    int tmp_V = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.dp_operation) {
            op2 = ((ins.with_zero) ? FPZero(0, 64) : m_ctx.readDoubleRegister(ins.m));
            std::tie(tmp_N, tmp_Z, tmp_C, tmp_V) = FPCompare(m_ctx.readDoubleRegister(ins.d), op2, ins.quiet_nan_exc, true);
            m_ctx.FPSCR.N = tmp_N, m_ctx.FPSCR.Z = tmp_Z, m_ctx.FPSCR.C = tmp_C, m_ctx.FPSCR.V = tmp_V;
        } else {
            op2 = ((ins.with_zero) ? FPZero(0, 32) : m_ctx.readSingleRegister(ins.m));
            std::tie(tmp_N, tmp_Z, tmp_C, tmp_V) = FPCompare(m_ctx.readSingleRegister(ins.d), op2, ins.quiet_nan_exc, true);
            m_ctx.FPSCR.N = tmp_N, m_ctx.FPSCR.Z = tmp_Z, m_ctx.FPSCR.C = tmp_C, m_ctx.FPSCR.V = tmp_V;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vcnt(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, BitCount(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_between_floating_point_and_integer_advancedsimd(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int operand = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                operand = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                if (ins.to_integer) {
                    result = FPToFixed(operand, ins.esize, 0, ins.unsigned_, ins.round_zero, false);
                } else {
                    result = FixedToFP(operand, ins.esize, 0, ins.unsigned_, ins.round_nearest, false);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_vcvtr_between_floating_point_and_integer_floating_point(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.to_integer) {
            if (ins.dp_operation) {
                m_ctx.writeSingleRegister(ins.d, FPToFixed(m_ctx.readDoubleRegister(ins.m), 32, 0, ins.unsigned_, ins.round_zero, true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPToFixed(m_ctx.readSingleRegister(ins.m), 32, 0, ins.unsigned_, ins.round_zero, true));
            }
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FixedToFP(m_ctx.readSingleRegister(ins.m), 64, 0, ins.unsigned_, ins.round_nearest, true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FixedToFP(m_ctx.readSingleRegister(ins.m), 32, 0, ins.unsigned_, ins.round_nearest, true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_between_floating_point_and_fixed_point_advancedsimd(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int operand = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                operand = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                if (ins.to_fixed) {
                    result = FPToFixed(operand, ins.esize, ins.frac_bits, ins.unsigned_, ins.round_zero, false);
                } else {
                    result = FixedToFP(operand, ins.esize, ins.frac_bits, ins.unsigned_, ins.round_nearest, false);
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_between_floating_point_and_fixed_point_floating_point(const ARMInstruction &ins) {
    int result = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.to_fixed) {
            if (ins.dp_operation) {
                result = FPToFixed(m_ctx.readDoubleRegister(ins.d), ins.size, ins.frac_bits, ins.unsigned_, ins.round_zero, true);
                m_ctx.writeDoubleRegister(ins.d, ((ins.unsigned_) ? ZeroExtend(result, 64) : SignExtend(result, 32)));
            } else {
                result = FPToFixed(m_ctx.readSingleRegister(ins.d), ins.size, ins.frac_bits, ins.unsigned_, ins.round_zero, true);
                m_ctx.writeSingleRegister(ins.d, ((ins.unsigned_) ? ZeroExtend(result, 32) : SignExtend(result, 32)));
            }
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FixedToFP(get_bits(m_ctx.readDoubleRegister(ins.d), (ins.size - 1), 0), 64, ins.frac_bits, ins.unsigned_, ins.round_nearest, true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FixedToFP(get_bits(m_ctx.readSingleRegister(ins.d), (ins.size - 1), 0), 32, ins.frac_bits, ins.unsigned_, ins.round_nearest, true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_between_double_precision_and_single_precision(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.double_to_single) {
            m_ctx.writeSingleRegister(ins.d, FPDoubleToSingle(m_ctx.readDoubleRegister(ins.m), true));
        } else {
            m_ctx.writeDoubleRegister(ins.d, FPSingleToDouble(m_ctx.readSingleRegister(ins.m), true));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vcvt_between_half_precision_and_single_precision_advancedsimd(const ARMInstruction &ins) {
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            if (ins.half_to_single) {
                m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), FPHalfToSingle(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), false));
            } else {
                m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, FPSingleToHalf(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), false));
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vcvtb_vcvtt(const ARMInstruction &ins) {
    int tmp_val = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.half_to_single) {
            m_ctx.writeSingleRegister(ins.d, FPHalfToSingle(get_bits(m_ctx.readSingleRegister(ins.m), (ins.lowbit + 15), ins.lowbit), true));
        } else {
            tmp_val = m_ctx.readSingleRegister(ins.d);
            set_bits(tmp_val, (ins.lowbit + 15), ins.lowbit, FPSingleToHalf(m_ctx.readSingleRegister(ins.m), true));
            m_ctx.writeSingleRegister(ins.d, tmp_val);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vdiv(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.dp_operation) {
            m_ctx.writeDoubleRegister(ins.d, FPDiv(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true));
        } else {
            m_ctx.writeSingleRegister(ins.d, FPDiv(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vdup_scalar(const ARMInstruction &ins) {
    int scalar = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        scalar = m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, scalar);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vdup_arm_core_register(const ARMInstruction &ins) {
    int scalar = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        scalar = get_bits(m_ctx.readRegularRegister(ins.t), (ins.esize - 1), 0);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, scalar);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_veor(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.n + r)) ^ m_ctx.readDoubleRegister((ins.m + r))));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vext(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
    }
    return true;
}

bool ARMInterpreter::interpret_vfma_vfms(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                    if (ins.op1_neg) {
                        op1 = FPNeg(op1);
                    }
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPMulAdd(m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize), op1, m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false));
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                op1 = ((ins.op1_neg) ? FPNeg(m_ctx.readDoubleRegister(ins.n)) : m_ctx.readDoubleRegister(ins.n));
                m_ctx.writeDoubleRegister(ins.d, FPMulAdd(m_ctx.readDoubleRegister(ins.d), op1, m_ctx.readDoubleRegister(ins.m), true));
            } else {
                op1 = ((ins.op1_neg) ? FPNeg(m_ctx.readSingleRegister(ins.n)) : m_ctx.readSingleRegister(ins.n));
                m_ctx.writeSingleRegister(ins.d, FPMulAdd(m_ctx.readSingleRegister(ins.d), op1, m_ctx.readSingleRegister(ins.m), true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vfnma_vfnms(const ARMInstruction &ins) {
    int op1 = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.dp_operation) {
            op1 = ((ins.op1_neg) ? FPNeg(m_ctx.readDoubleRegister(ins.n)) : m_ctx.readDoubleRegister(ins.n));
            m_ctx.writeDoubleRegister(ins.d, FPMulAdd(FPNeg(m_ctx.readDoubleRegister(ins.d)), op1, m_ctx.readDoubleRegister(ins.m), true));
        } else {
            op1 = ((ins.op1_neg) ? FPNeg(m_ctx.readSingleRegister(ins.n)) : m_ctx.readSingleRegister(ins.n));
            m_ctx.writeSingleRegister(ins.d, FPMulAdd(FPNeg(m_ctx.readSingleRegister(ins.d)), op1, m_ctx.readSingleRegister(ins.m), true));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vhadd_vhsub(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize));
                op2 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                result = ((ins.add) ? (op1 + op2) : (op1 - op2));
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, ins.esize, 1));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld1_multiple_single_elements(const ARMInstruction &ins) {
    int address = 0;
    int data = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (8 * ins.regs))));
        }
        data = Zeros(64);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if ((ins.ebytes != 8)) {
                    set_bits(data, (ins.esize - 1), 0, m_ctx.read_MemU(address, ins.ebytes));
                } else {
                    set_bits(data, 31, 0, ((BigEndian()) ? m_ctx.read_MemU((address + 4), 4) : m_ctx.read_MemU(address, 4)));
                    set_bits(data, 63, 32, ((BigEndian()) ? m_ctx.read_MemU(address, 4) : m_ctx.read_MemU((address + 4), 4)));
                }
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(data, (ins.esize - 1), 0));
                address = (address + ins.ebytes);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld1_single_element_to_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : ins.ebytes)));
        }
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
    }
    return true;
}

bool ARMInterpreter::interpret_vld1_single_element_to_all_lanes(const ARMInstruction &ins) {
    int address = 0;
    int replicated_element = 0;
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : ins.ebytes)));
        }
        replicated_element = Replicate(m_ctx.read_MemU(address, ins.ebytes), ins.elements);
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), replicated_element);
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld2_multiple_2_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (16 * ins.regs))));
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d2 + r)), e, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
                address = (address + (2 * ins.ebytes));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld2_single_2_element_structure_to_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (2 * ins.ebytes))));
        }
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
    }
    return true;
}

bool ARMInterpreter::interpret_vld2_single_2_element_structure_to_all_lanes(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (2 * ins.ebytes))));
        }
        m_ctx.writeDoubleRegister(ins.d, Replicate(m_ctx.read_MemU(address, ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d2, Replicate(m_ctx.read_MemU((address + ins.ebytes), ins.ebytes), ins.elements));
    }
    return true;
}

bool ARMInterpreter::interpret_vld3_multiple_3_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : 24)));
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d2), e, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d3), e, ins.esize, m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes));
            address = (address + (3 * ins.ebytes));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld3_single_3_element_structure_to_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (3 * ins.ebytes))));
        }
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d3), ins.index, ins.esize, m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes));
    }
    return true;
}

bool ARMInterpreter::interpret_vld3_single_3_element_structure_to_all_lanes(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (3 * ins.ebytes))));
        }
        m_ctx.writeDoubleRegister(ins.d, Replicate(m_ctx.read_MemU(address, ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d2, Replicate(m_ctx.read_MemU((address + ins.ebytes), ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d3, Replicate(m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes), ins.elements));
    }
    return true;
}

bool ARMInterpreter::interpret_vld4_multiple_4_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : 32)));
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d2), e, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d3), e, ins.esize, m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d4), e, ins.esize, m_ctx.read_MemU((address + (3 * ins.ebytes)), ins.ebytes));
            address = (address + (4 * ins.ebytes));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vld4_single_4_element_structure_to_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (4 * ins.ebytes))));
        }
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize, m_ctx.read_MemU(address, ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize, m_ctx.read_MemU((address + ins.ebytes), ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d3), ins.index, ins.esize, m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes));
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d4), ins.index, ins.esize, m_ctx.read_MemU((address + (3 * ins.ebytes)), ins.ebytes));
    }
    return true;
}

bool ARMInterpreter::interpret_vld4_single_4_element_structure_to_all_lanes(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (4 * ins.ebytes))));
        }
        m_ctx.writeDoubleRegister(ins.d, Replicate(m_ctx.read_MemU(address, ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d2, Replicate(m_ctx.read_MemU((address + ins.ebytes), ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d3, Replicate(m_ctx.read_MemU((address + (2 * ins.ebytes)), ins.ebytes), ins.elements));
        m_ctx.writeDoubleRegister(ins.d4, Replicate(m_ctx.read_MemU((address + (3 * ins.ebytes)), ins.ebytes), ins.elements));
    }
    return true;
}

bool ARMInterpreter::interpret_vldm(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;
    int word1 = 0;
    int word2 = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(ins.n);
        address = ((ins.add) ? m_ctx.readRegularRegister(ins.n) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32)));
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            if (ins.single_regs) {
                m_ctx.writeSingleRegister((ins.d + r), m_ctx.read_MemA(address, 4));
                address = (address + 4);
            } else {
                word1 = m_ctx.read_MemA(address, 4);
                word2 = m_ctx.read_MemA((address + 4), 4);
                address = (address + 8);
                m_ctx.writeDoubleRegister((ins.d + r), ((BigEndian()) ? Concatenate(word1, word2, 32) : Concatenate(word2, word1, 32)));
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vldr(const ARMInstruction &ins) {
    int base = 0;
    int address = 0;
    int word1 = 0;
    int word2 = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(ins.n);
        base = (((ins.n == 15)) ? Align(m_ctx.readRegularRegister(15), 4) : m_ctx.readRegularRegister(ins.n));
        address = ((ins.add) ? (base + ins.imm32) : (base - ins.imm32));
        if (ins.single_reg) {
            m_ctx.writeSingleRegister(ins.d, m_ctx.read_MemA(address, 4));
        } else {
            word1 = m_ctx.read_MemA(address, 4);
            word2 = m_ctx.read_MemA((address + 4), 4);
            m_ctx.writeDoubleRegister(ins.d, ((BigEndian()) ? Concatenate(word1, word2, 32) : Concatenate(word2, word1, 32)));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmax_vmin_integer(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize));
                op2 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                result = ((ins.maximum) ? Max(op1, op2) : Min(op1, op2));
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmax_vmin_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((ins.maximum) ? FPMax(op1, op2, false) : FPMin(op1, op2, false)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmla_vmlal_vmls_vmlsl_integer(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int product = 0;
    int addend = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                product = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize)) * ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)));
                addend = ((ins.add) ? product : -product);
                if (ins.long_destination) {
                    m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), (m_ctx.readElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize)) + addend));
                } else {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) + addend));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmla_vmls_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int product = 0;
    int addend = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    product = FPMul(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false);
                    addend = ((ins.add) ? product : FPNeg(product));
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPAdd(m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize), addend, false));
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                addend = ((ins.add) ? FPMul(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true) : FPNeg(FPMul(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true)));
                m_ctx.writeDoubleRegister(ins.d, FPAdd(m_ctx.readDoubleRegister(ins.d), addend, true));
            } else {
                addend = ((ins.add) ? FPMul(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true) : FPNeg(FPMul(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true)));
                m_ctx.writeSingleRegister(ins.d, FPAdd(m_ctx.readSingleRegister(ins.d), addend, true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmla_vmlal_vmls_vmlsl_by_scalar(const ARMInstruction &ins) {
    int op2 = 0;
    int op2val = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op1val = 0;
    int fp_addend = 0;
    int addend = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        op2 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize);
        op2val = ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize));
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op1val = ((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize));
                if (ins.floating_point) {
                    fp_addend = ((ins.add) ? FPMul(op1, op2, false) : FPNeg(FPMul(op1, op2, false)));
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPAdd(m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize), fp_addend, false));
                } else {
                    addend = ((ins.add) ? (op1val * op2val) : (-op1val * op2val));
                    if (ins.long_destination) {
                        m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), (m_ctx.readElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize)) + addend));
                    } else {
                        m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) + addend));
                    }
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_immediate(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.single_register) {
            m_ctx.writeSingleRegister(ins.d, ins.imm32);
        } else {
            for (r = 0; r < (ins.regs - 1); ++r) {
                m_ctx.writeDoubleRegister((ins.d + r), ins.imm64);
            }
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.single_register) {
            m_ctx.writeSingleRegister(ins.d, m_ctx.readSingleRegister(ins.m));
        } else {
            for (r = 0; r < (ins.regs - 1); ++r) {
                m_ctx.writeDoubleRegister((ins.d + r), m_ctx.readDoubleRegister((ins.m + r)));
            }
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_arm_core_register_to_scalar(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize, get_bits(m_ctx.readRegularRegister(ins.t), (ins.esize - 1), 0));
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_scalar_to_arm_core_register(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.unsigned_) {
            m_ctx.writeRegularRegister(ins.t, ZeroExtend(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ins.index, ins.esize), 32));
        } else {
            m_ctx.writeRegularRegister(ins.t, SignExtend(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ins.index, ins.esize), ins.esize));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_between_arm_core_register_and_single_precision_register(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.to_arm_register) {
            m_ctx.writeRegularRegister(ins.t, m_ctx.readSingleRegister(ins.n));
        } else {
            m_ctx.writeSingleRegister(ins.n, m_ctx.readRegularRegister(ins.t));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_between_two_arm_core_registers_and_two_single_precision_registers(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.to_arm_registers) {
            m_ctx.writeRegularRegister(ins.t, m_ctx.readSingleRegister(ins.m));
            m_ctx.writeRegularRegister(ins.t2, m_ctx.readSingleRegister((ins.m + 1)));
        } else {
            m_ctx.writeSingleRegister(ins.m, m_ctx.readRegularRegister(ins.t));
            m_ctx.writeSingleRegister((ins.m + 1), m_ctx.readRegularRegister(ins.t2));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmov_between_two_arm_core_registers_and_a_doubleword_extension_register(const ARMInstruction &ins) {
    int tmp_val = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.to_arm_registers) {
            m_ctx.writeRegularRegister(ins.t, get_bits(m_ctx.readDoubleRegister(ins.m), 31, 0));
            m_ctx.writeRegularRegister(ins.t2, get_bits(m_ctx.readDoubleRegister(ins.m), 63, 32));
        } else {
            tmp_val = m_ctx.readDoubleRegister(ins.m);
            set_bits(tmp_val, 31, 0, m_ctx.readRegularRegister(ins.t));
            set_bits(tmp_val, 63, 32, m_ctx.readRegularRegister(ins.t2));
            m_ctx.writeDoubleRegister(ins.m, tmp_val);
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmovl(const ARMInstruction &ins) {
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize));
            m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), get_bits(result, ((2 * ins.esize) - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmovn(const ARMInstruction &ins) {
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), (ins.esize - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmrs(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        SerializeVFP();
        VFPExcBarrier();
        if ((ins.t != 15)) {
            m_ctx.writeRegularRegister(ins.t, m_ctx.FPSCR);
        } else {
            m_ctx.APSR.N = m_ctx.FPSCR.N;
            m_ctx.APSR.Z = m_ctx.FPSCR.Z;
            m_ctx.APSR.C = m_ctx.FPSCR.C;
            m_ctx.APSR.V = m_ctx.FPSCR.V;
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmsr(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        SerializeVFP();
        VFPExcBarrier();
        m_ctx.FPSCR = m_ctx.readRegularRegister(ins.t);
    }
    return true;
}

bool ARMInterpreter::interpret_vmul_vmull_integer_and_polynomial(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op1val = 0;
    int op2 = 0;
    int op2val = 0;
    int product = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op1val = ((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize));
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize);
                op2val = ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize));
                if (ins.polynomial) {
                    product = PolynomialMult(op1, op2);
                } else {
                    tmp = (op1val * op2val);
                    product = get_bits(tmp, ((2 * ins.esize) - 1), 0);
                }
                if (ins.long_destination) {
                    m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), product);
                } else {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(product, (ins.esize - 1), 0));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmul_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPMul(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false));
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FPMul(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPMul(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vmul_vmull_by_scalar(const ARMInstruction &ins) {
    int op2 = 0;
    int op2val = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op1val = 0;
    int tmp = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        op2 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize);
        op2val = ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize));
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize);
                op1val = ((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize));
                if (ins.floating_point) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPMul(op1, op2, false));
                } else {
                    tmp = (op1val * op2val);
                    if (ins.long_destination) {
                        m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), get_bits(tmp, ((2 * ins.esize) - 1), 0));
                    } else {
                        m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(tmp, (ins.esize - 1), 0));
                    }
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmvn_immediate(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), NOT(ins.imm64, 32));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vmvn_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), NOT(m_ctx.readDoubleRegister((ins.m + r)), 64));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vneg(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    if (ins.floating_point) {
                        m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPNeg(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
                    } else {
                        result = -SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize);
                        m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
                    }
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FPNeg(m_ctx.readDoubleRegister(ins.m)));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPNeg(m_ctx.readSingleRegister(ins.m)));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vnmla_vnmls_vnmul(const ARMInstruction &ins) {
    int product = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.dp_operation) {
            product = FPMul(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true);
            switch (ins.type) {
                case VFPNegMul_VNMLA:
                    m_ctx.writeDoubleRegister(ins.d, FPAdd(FPNeg(m_ctx.readDoubleRegister(ins.d)), FPNeg(product), true));
                    break;
                
                case VFPNegMul_VNMLS:
                    m_ctx.writeDoubleRegister(ins.d, FPAdd(FPNeg(m_ctx.readDoubleRegister(ins.d)), product, true));
                    break;
                
                case VFPNegMul_VNMUL:
                    m_ctx.writeDoubleRegister(ins.d, FPNeg(product));
                    break;
                
            }
            
        } else {
            product = FPMul(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true);
            switch (ins.type) {
                case VFPNegMul_VNMLA:
                    m_ctx.writeSingleRegister(ins.d, FPAdd(FPNeg(m_ctx.readSingleRegister(ins.d)), FPNeg(product), true));
                    break;
                
                case VFPNegMul_VNMLS:
                    m_ctx.writeSingleRegister(ins.d, FPAdd(FPNeg(m_ctx.readSingleRegister(ins.d)), product, true));
                    break;
                
                case VFPNegMul_VNMUL:
                    m_ctx.writeSingleRegister(ins.d, FPNeg(product));
                    break;
                
            }
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vorn_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.n + r)) | NOT(m_ctx.readDoubleRegister((ins.m + r)), 64)));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vorr_immediate(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.d + r)) | ins.imm64));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vorr_register(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            m_ctx.writeDoubleRegister((ins.d + r), (m_ctx.readDoubleRegister((ins.n + r)) | m_ctx.readDoubleRegister((ins.m + r))));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vpadal(const ARMInstruction &ins) {
    int h = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        h = (ins.elements / 2);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (h - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), (2 * e), ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), ((2 * e) + 1), ins.esize);
                result = (((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize)) + ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize)));
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, (2 * ins.esize), (m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, (2 * ins.esize)) + result));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vpadd_integer(const ARMInstruction &ins) {
    int dest = 0;
    int h = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        dest = 0;
        h = (ins.elements / 2);
        for (e = 0; e < (h - 1); ++e) {
            m_ctx.writeElement(dest, e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), (2 * e), ins.esize) + m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ((2 * e) + 1), ins.esize)));
            m_ctx.writeElement(dest, (e + h), ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), (2 * e), ins.esize) + m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ((2 * e) + 1), ins.esize)));
        }
        
        m_ctx.writeDoubleRegister(ins.d, dest);
    }
    return true;
}

bool ARMInterpreter::interpret_vpadd_floating_point(const ARMInstruction &ins) {
    int dest = 0;
    int h = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        dest = 0;
        h = (ins.elements / 2);
        for (e = 0; e < (h - 1); ++e) {
            m_ctx.writeElement(dest, e, ins.esize, FPAdd(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), (2 * e), ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ((2 * e) + 1), ins.esize), false));
            m_ctx.writeElement(dest, (e + h), ins.esize, FPAdd(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), (2 * e), ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ((2 * e) + 1), ins.esize), false));
        }
        
        m_ctx.writeDoubleRegister(ins.d, dest);
    }
    return true;
}

bool ARMInterpreter::interpret_vpaddl(const ARMInstruction &ins) {
    int h = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        h = (ins.elements / 2);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (h - 1); ++e) {
                op1 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), (2 * e), ins.esize);
                op2 = m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), ((2 * e) + 1), ins.esize);
                result = (((ins.unsigned_) ? UInt(op1) : SInt(op1, ins.esize)) + ((ins.unsigned_) ? UInt(op2) : SInt(op2, ins.esize)));
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, (2 * ins.esize), get_bits(result, ((2 * ins.esize) - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vpmax_vpmin_integer(const ARMInstruction &ins) {
    int dest = 0;
    int h = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        dest = 0;
        h = (ins.elements / 2);
        for (e = 0; e < (h - 1); ++e) {
            op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), (2 * e), ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), (2 * e), ins.esize), ins.esize));
            op2 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ((2 * e) + 1), ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ((2 * e) + 1), ins.esize), ins.esize));
            result = ((ins.maximum) ? Max(op1, op2) : Min(op1, op2));
            m_ctx.writeElement(dest, e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), (2 * e), ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), (2 * e), ins.esize), ins.esize));
            op2 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ((2 * e) + 1), ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ((2 * e) + 1), ins.esize), ins.esize));
            result = ((ins.maximum) ? Max(op1, op2) : Min(op1, op2));
            m_ctx.writeElement(dest, (e + h), ins.esize, get_bits(result, (ins.esize - 1), 0));
            m_ctx.writeDoubleRegister(ins.d, dest);
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vpmax_vpmin_floating_point(const ARMInstruction &ins) {
    int dest = 0;
    int h = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        dest = 0;
        h = (ins.elements / 2);
        for (e = 0; e < (h - 1); ++e) {
            op1 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), (2 * e), ins.esize);
            op2 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), ((2 * e) + 1), ins.esize);
            m_ctx.writeElement(dest, e, ins.esize, ((ins.maximum) ? FPMax(op1, op2, false) : FPMin(op1, op2, false)));
            op1 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), (2 * e), ins.esize);
            op2 = m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ((2 * e) + 1), ins.esize);
            m_ctx.writeElement(dest, (e + h), ins.esize, ((ins.maximum) ? FPMax(op1, op2, false) : FPMin(op1, op2, false)));
            m_ctx.writeDoubleRegister(ins.d, dest);
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vpop(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;
    int word1 = 0;
    int word2 = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(13);
        address = m_ctx.readRegularRegister(13);
        m_ctx.writeRegularRegister(13, (address + ins.imm32));
        if (ins.single_regs) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                m_ctx.writeSingleRegister((ins.d + r), m_ctx.read_MemA(address, 4));
                address = (address + 4);
            }
            
        } else {
            for (r = 0; r < (ins.regs - 1); ++r) {
                word1 = m_ctx.read_MemA(address, 4);
                word2 = m_ctx.read_MemA((address + 4), 4);
                address = (address + 8);
                m_ctx.writeDoubleRegister((ins.d + r), ((BigEndian()) ? Concatenate(word1, word2, 32) : Concatenate(word2, word1, 32)));
            }
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vpush(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(13);
        address = (m_ctx.readRegularRegister(13) - ins.imm32);
        m_ctx.writeRegularRegister(13, (m_ctx.readRegularRegister(13) - ins.imm32));
        if (ins.single_regs) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                m_ctx.write_MemA(address, 4, m_ctx.readSingleRegister((ins.d + r)));
                address = (address + 4);
            }
            
        } else {
            for (r = 0; r < (ins.regs - 1); ++r) {
                m_ctx.write_MemA(address, 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister((ins.d + r)), 63, 32) : get_bits(m_ctx.readDoubleRegister((ins.d + r)), 31, 0)));
                m_ctx.write_MemA((address + 4), 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister((ins.d + r)), 31, 0) : get_bits(m_ctx.readDoubleRegister((ins.d + r)), 63, 32)));
                address = (address + 8);
            }
            
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vqabs(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int result = 0;
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = Abs(SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                std::tie(tmp_0, sat) = SignedSatQ(result, ins.esize);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqadd(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int sum = 0;
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                sum = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize)) + ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)));
                std::tie(tmp_0, sat) = SatQ(sum, ins.esize, ins.unsigned_);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqdmlal_vqdmlsl(const ARMInstruction &ins) {
    int op2 = 0;
    int e = 0;
    int op1 = 0;
    int product = 0;
    int sat1 = 0;
    int result = 0;
    int tmp_0 = 0;
    int sat2 = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        if (ins.scalar_form) {
            op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize), ins.esize);
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            if (!ins.scalar_form) {
                op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize);
            }
            op1 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize), ins.esize);
            std::tie(product, sat1) = SignedSatQ(((2 * op1) * op2), (2 * ins.esize));
            if (ins.add) {
                result = (SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize)), (2 * ins.esize)) + SInt(product, (2 * ins.esize)));
            } else {
                result = (SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize)), (2 * ins.esize)) - SInt(product, (2 * ins.esize)));
            }
            std::tie(tmp_0, sat2) = SignedSatQ(result, (2 * ins.esize));
            if ((sat1 || sat2)) {
                m_ctx.FPSCR.QC = 1;
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqdmulh(const ARMInstruction &ins) {
    int op2 = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        if (ins.scalar_form) {
            op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize), ins.esize);
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (!ins.scalar_form) {
                    op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize);
                }
                op1 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize);
                std::tie(result, sat) = SignedSatQ((((2 * op1) * op2) >> ins.esize), ins.esize);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqdmull(const ARMInstruction &ins) {
    int op2 = 0;
    int e = 0;
    int op1 = 0;
    int product = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        if (ins.scalar_form) {
            op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize), ins.esize);
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            if (!ins.scalar_form) {
                op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize);
            }
            op1 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize), ins.esize);
            std::tie(product, sat) = SignedSatQ(((2 * op1) * op2), (2 * ins.esize));
            m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), product);
            if (sat) {
                m_ctx.FPSCR.QC = 1;
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqmovn_vqmovun(const ARMInstruction &ins) {
    int e = 0;
    int operand = 0;
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            operand = ((ins.src_unsigned) ? UInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize))) : SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), (2 * ins.esize)));
            std::tie(tmp_0, sat) = SatQ(operand, ins.esize, ins.dest_unsigned);
            if (sat) {
                m_ctx.FPSCR.QC = 1;
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqneg(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int result = 0;
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = -SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize);
                std::tie(tmp_0, sat) = SignedSatQ(result, ins.esize);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqrdmulh(const ARMInstruction &ins) {
    int round_const = 0;
    int op2 = 0;
    int r = 0;
    int e = 0;
    int op1 = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.esize - 1));
        if (ins.scalar_form) {
            op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), ins.index, ins.esize), ins.esize);
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize);
                if (!ins.scalar_form) {
                    op2 = SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize);
                }
                std::tie(result, sat) = SignedSatQ(((((2 * op1) * op2) + round_const) >> ins.esize), ins.esize);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqrshl(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int shift = 0;
    int round_const = 0;
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shift = SInt(get_bits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), 7, 0), 8);
                round_const = (1 << (-1 - shift));
                operand = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                std::tie(result, sat) = SatQ(((operand + round_const) << shift), ins.esize, ins.unsigned_);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqrshrn_vqrshrun(const ARMInstruction &ins) {
    int round_const = 0;
    int e = 0;
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.shift_amount - 1));
        for (e = 0; e < (ins.elements - 1); ++e) {
            operand = ((ins.src_unsigned) ? UInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize))) : SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), (2 * ins.esize)));
            std::tie(result, sat) = SatQ(((operand + round_const) >> ins.shift_amount), ins.esize, ins.dest_unsigned);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, result);
            if (sat) {
                m_ctx.FPSCR.QC = 1;
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqshl_register(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int shift = 0;
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shift = SInt(get_bits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), 7, 0), 8);
                operand = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                std::tie(result, sat) = SatQ((operand << shift), ins.esize, ins.unsigned_);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqshl_vqshlu_immediate(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                operand = ((ins.src_unsigned) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                std::tie(result, sat) = SatQ((operand << ins.shift_amount), ins.esize, ins.dest_unsigned);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, result);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqshrn_vqshrun(const ARMInstruction &ins) {
    int e = 0;
    int operand = 0;
    int result = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            operand = ((ins.src_unsigned) ? UInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize))) : SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), (2 * ins.esize)));
            std::tie(result, sat) = SatQ((operand >> ins.shift_amount), ins.esize, ins.dest_unsigned);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, result);
            if (sat) {
                m_ctx.FPSCR.QC = 1;
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vqsub(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int diff = 0;
    int tmp_0 = 0;
    int sat = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                diff = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize)) - ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)));
                std::tie(tmp_0, sat) = SatQ(diff, ins.esize, ins.unsigned_);
                if (sat) {
                    m_ctx.FPSCR.QC = 1;
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vraddhn(const ARMInstruction &ins) {
    int round_const = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.esize - 1));
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = ((m_ctx.readElement(m_ctx.readQuadRegister((ins.n >> 1)), e, (2 * ins.esize)) + m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize))) + round_const);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, ((2 * ins.esize) - 1), ins.esize));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrecpe(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPRecipEstimate(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
                } else {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, UnsignedRecipEstimate(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrecps(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPRecipStep(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrev16_vrev32_vrev64(const ARMInstruction &ins) {
    int dest = 0;
    int r = 0;
    int e = 0;
    int e_bits = 0;
    int d_bits = 0;
    int i = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        dest = 0;
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                e_bits = get_bits(e, (ins.esize - 1), 0);
                d_bits = (e_bits ^ ins.reverse_mask);
                i = UInt(d_bits);
                m_ctx.writeElement(dest, i, ins.esize, m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize));
            }
            
            m_ctx.writeDoubleRegister((ins.d + r), dest);
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrhadd(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int op1 = 0;
    int op2 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), ins.esize));
                op2 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize));
                result = ((op1 + op2) + 1);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, ins.esize, 1));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrshl(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int shift = 0;
    int round_const = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shift = SInt(get_bits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), 7, 0), 8);
                round_const = (1 << (-shift - 1));
                result = ((((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) + round_const) << shift);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrshr(const ARMInstruction &ins) {
    int round_const = 0;
    int r = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.shift_amount - 1));
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = ((((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) + round_const) >> ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrshrn(const ARMInstruction &ins) {
    int round_const = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.shift_amount - 1));
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = LSR((m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)) + round_const), ins.shift_amount);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrsqrte(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (ins.floating_point) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPRSqrtEstimate(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
                } else {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, UnsignedRSqrtEstimate(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrsqrts(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPRSqrtStep(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrsra(const ARMInstruction &ins) {
    int round_const = 0;
    int r = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.shift_amount - 1));
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = ((((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) + round_const) >> ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) + result));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vrsubhn(const ARMInstruction &ins) {
    int round_const = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        round_const = (1 << (ins.esize - 1));
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = ((m_ctx.readElement(m_ctx.readQuadRegister((ins.n >> 1)), e, (2 * ins.esize)) - m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize))) + round_const);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, ((2 * ins.esize) - 1), ins.esize));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vshl_immediate(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, LSL(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.shift_amount));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vshl_register(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int shift = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shift = SInt(get_bits(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), 7, 0), 8);
                result = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) << shift);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vshll(const ARMInstruction &ins) {
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize)) << ins.shift_amount);
            m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), get_bits(result, ((2 * ins.esize) - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vshr(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) >> ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vshrn(const ARMInstruction &ins) {
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = LSR(m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)), ins.shift_amount);
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, (ins.esize - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vsli(const ARMInstruction &ins) {
    int mask = 0;
    int r = 0;
    int e = 0;
    int shifted_op = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        mask = LSL(Ones(ins.esize), ins.shift_amount);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shifted_op = LSL(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) & NOT(mask, ins.esize)) | shifted_op));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vsqrt(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        if (ins.dp_operation) {
            m_ctx.writeDoubleRegister(ins.d, FPSqrt(m_ctx.readDoubleRegister(ins.m)));
        } else {
            m_ctx.writeSingleRegister(ins.d, FPSqrt(m_ctx.readSingleRegister(ins.m)));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vsra(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                result = (((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.esize)) >> ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) + result));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vsri(const ARMInstruction &ins) {
    int mask = 0;
    int r = 0;
    int e = 0;
    int shifted_op = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        mask = LSR(Ones(ins.esize), ins.shift_amount);
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                shifted_op = LSR(m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), ins.shift_amount);
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, ((m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize) & NOT(mask, ins.esize)) | shifted_op));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vst1_multiple_single_elements(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;
    int e = 0;
    int data = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (8 * ins.regs))));
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if ((ins.ebytes != 8)) {
                    m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize));
                } else {
                    data = m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize);
                    m_ctx.write_MemU(address, 4, ((BigEndian()) ? get_bits(data, 63, 32) : get_bits(data, 31, 0)));
                    m_ctx.write_MemU((address + 4), 4, ((BigEndian()) ? get_bits(data, 31, 0) : get_bits(data, 63, 32)));
                }
                address = (address + ins.ebytes);
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vst1_single_element_from_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : ins.ebytes)));
        }
        m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize));
    }
    return true;
}

bool ARMInterpreter::interpret_vst2_multiple_2_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (16 * ins.regs))));
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize));
                m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister((ins.d2 + r)), e, ins.esize));
                address = (address + (2 * ins.ebytes));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vst2_single_2_element_structure_from_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (2 * ins.ebytes))));
        }
        m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize));
        m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize));
    }
    return true;
}

bool ARMInterpreter::interpret_vst3_multiple_3_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : 24)));
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize));
            m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d2), e, ins.esize));
            m_ctx.write_MemU((address + (2 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d3), e, ins.esize));
            address = (address + (3 * ins.ebytes));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vst3_single_3_element_structure_from_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (3 * ins.ebytes))));
        }
        m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize));
        m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize));
        m_ctx.write_MemU((address + (2 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d3), ins.index, ins.esize));
    }
    return true;
}

bool ARMInterpreter::interpret_vst4_multiple_4_element_structures(const ARMInstruction &ins) {
    int address = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE(ins.n);
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : 32)));
        }
        for (e = 0; e < (ins.elements - 1); ++e) {
            m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize));
            m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d2), e, ins.esize));
            m_ctx.write_MemU((address + (2 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d3), e, ins.esize));
            m_ctx.write_MemU((address + (3 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d4), e, ins.esize));
            address = (address + (4 * ins.ebytes));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vst4_single_4_element_structure_from_one_lane(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        NullCheckIfThumbEE();
        address = m_ctx.readRegularRegister(ins.n);
        if (((address % ins.alignment) != 0)) {
            GenerateAlignmentException();
        }
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, (m_ctx.readRegularRegister(ins.n) + ((ins.register_index) ? m_ctx.readRegularRegister(ins.m) : (4 * ins.ebytes))));
        }
        m_ctx.write_MemU(address, ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), ins.index, ins.esize));
        m_ctx.write_MemU((address + ins.ebytes), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d2), ins.index, ins.esize));
        m_ctx.write_MemU((address + (2 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d3), ins.index, ins.esize));
        m_ctx.write_MemU((address + (3 * ins.ebytes)), ins.ebytes, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d4), ins.index, ins.esize));
    }
    return true;
}

bool ARMInterpreter::interpret_vstm(const ARMInstruction &ins) {
    int address = 0;
    int r = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(ins.n);
        address = ((ins.add) ? m_ctx.readRegularRegister(ins.n) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        if (ins.wback) {
            m_ctx.writeRegularRegister(ins.n, ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32)));
        }
        for (r = 0; r < (ins.regs - 1); ++r) {
            if (ins.single_regs) {
                m_ctx.write_MemA(address, 4, m_ctx.readSingleRegister((ins.d + r)));
                address = (address + 4);
            } else {
                m_ctx.write_MemA(address, 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister((ins.d + r)), 63, 32) : get_bits(m_ctx.readDoubleRegister((ins.d + r)), 31, 0)));
                m_ctx.write_MemA((address + 4), 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister((ins.d + r)), 31, 0) : get_bits(m_ctx.readDoubleRegister((ins.d + r)), 63, 32)));
                address = (address + 8);
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vstr(const ARMInstruction &ins) {
    int address = 0;

    if (ConditionPassed()) {
        CheckVFPEnabled(true);
        NullCheckIfThumbEE(ins.n);
        address = ((ins.add) ? (m_ctx.readRegularRegister(ins.n) + ins.imm32) : (m_ctx.readRegularRegister(ins.n) - ins.imm32));
        if (ins.single_reg) {
            m_ctx.write_MemA(address, 4, m_ctx.readSingleRegister(ins.d));
        } else {
            m_ctx.write_MemA(address, 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister(ins.d), 63, 32) : get_bits(m_ctx.readDoubleRegister(ins.d), 31, 0)));
            m_ctx.write_MemA((address + 4), 4, ((BigEndian()) ? get_bits(m_ctx.readDoubleRegister(ins.d), 31, 0) : get_bits(m_ctx.readDoubleRegister(ins.d), 63, 32)));
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vsub_integer(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, (m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize) - m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)));
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vsub_floating_point(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDOrVFPEnabled(true, ins.advsimd);
        if (ins.advsimd) {
            for (r = 0; r < (ins.regs - 1); ++r) {
                for (e = 0; e < (ins.elements - 1); ++e) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, FPSub(m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize), m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize), false));
                }
                
            }
            
        } else {
            if (ins.dp_operation) {
                m_ctx.writeDoubleRegister(ins.d, FPSub(m_ctx.readDoubleRegister(ins.n), m_ctx.readDoubleRegister(ins.m), true));
            } else {
                m_ctx.writeSingleRegister(ins.d, FPSub(m_ctx.readSingleRegister(ins.n), m_ctx.readSingleRegister(ins.m), true));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vsubhn(const ARMInstruction &ins) {
    int e = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            result = (m_ctx.readElement(m_ctx.readQuadRegister((ins.n >> 1)), e, (2 * ins.esize)) - m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, (2 * ins.esize)));
            m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, get_bits(result, ((2 * ins.esize) - 1), ins.esize));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vsubl_vsubw(const ARMInstruction &ins) {
    int e = 0;
    int op1 = 0;
    int result = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (e = 0; e < (ins.elements - 1); ++e) {
            if (ins.is_vsubw) {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.n >> 1)), e, (2 * ins.esize))) : SInt(m_ctx.readElement(m_ctx.readQuadRegister((ins.n >> 1)), e, (2 * ins.esize)), (2 * ins.esize)));
            } else {
                op1 = ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.n), e, ins.esize), ins.esize));
            }
            result = (op1 - ((ins.unsigned_) ? UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize)) : SInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize), ins.esize)));
            m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, (2 * ins.esize), get_bits(result, ((2 * ins.esize) - 1), 0));
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vswp(const ARMInstruction &ins) {
    int r = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            if ((ins.d == ins.m)) {
                m_ctx.writeDoubleRegister((ins.d + r), UNKNOWN_VALUE);
            } else {
                m_ctx.writeDoubleRegister((ins.d + r), m_ctx.readDoubleRegister((ins.m + r)));
                m_ctx.writeDoubleRegister((ins.m + r), m_ctx.readDoubleRegister((ins.d + r)));
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vtbl_vtbx(const ARMInstruction &ins) {
    int table3 = 0;
    int table2 = 0;
    int table1 = 0;
    int table = 0;
    int i = 0;
    int index = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        table3 = (((ins.length == 4)) ? m_ctx.readDoubleRegister((ins.n + 3)) : Zeros(64));
        table2 = (((ins.length >= 3)) ? m_ctx.readDoubleRegister((ins.n + 2)) : Zeros(64));
        table1 = (((ins.length >= 2)) ? m_ctx.readDoubleRegister((ins.n + 1)) : Zeros(64));
        table = Concatenate(Concatenate(Concatenate(table3, table2, 64), table1, 64), m_ctx.readDoubleRegister(ins.n), 64);
        for (i = 0; i < 7; ++i) {
            index = UInt(m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), i, 8));
            if ((index < (8 * ins.length))) {
                m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), i, 8, m_ctx.readElement(table, index, 8));
            } else {
                if (ins.is_vtbl) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), i, 8, Zeros(8));
                }
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vtrn(const ARMInstruction &ins) {
    int h = 0;
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        h = (ins.elements / 2);
        for (r = 0; r < (ins.regs - 1); ++r) {
            if ((ins.d == ins.m)) {
                m_ctx.writeDoubleRegister((ins.d + r), UNKNOWN_VALUE);
            } else {
                for (e = 0; e < (h - 1); ++e) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), ((2 * e) + 1), ins.esize, m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), (2 * e), ins.esize));
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.m + r)), (2 * e), ins.esize, m_ctx.readElement(m_ctx.readDoubleRegister((ins.d + r)), ((2 * e) + 1), ins.esize));
                }
                
            }
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vtst(const ARMInstruction &ins) {
    int r = 0;
    int e = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        for (r = 0; r < (ins.regs - 1); ++r) {
            for (e = 0; e < (ins.elements - 1); ++e) {
                if (!IsZero((m_ctx.readElement(m_ctx.readDoubleRegister((ins.n + r)), e, ins.esize) & m_ctx.readElement(m_ctx.readDoubleRegister((ins.m + r)), e, ins.esize)))) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, Ones(ins.esize));
                } else {
                    m_ctx.writeElement(m_ctx.readDoubleRegister((ins.d + r)), e, ins.esize, Zeros(ins.esize));
                }
            }
            
        }
        
    }
    return true;
}

bool ARMInterpreter::interpret_vuzp(const ARMInstruction &ins) {
    int zipped_q = 0;
    int e = 0;
    int zipped_d = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        if (ins.quadword_operation) {
            if ((ins.d == ins.m)) {
                m_ctx.writeQuadRegister((ins.d >> 1), UNKNOWN_VALUE);
                m_ctx.writeQuadRegister((ins.m >> 1), UNKNOWN_VALUE);
            } else {
                zipped_q = Concatenate(m_ctx.readQuadRegister((ins.m >> 1)), m_ctx.readQuadRegister((ins.d >> 1)), 128);
                for (e = 0; e < ((128 / ins.esize) - 1); ++e) {
                    m_ctx.writeElement(m_ctx.readQuadRegister((ins.d >> 1)), e, ins.esize, m_ctx.readElement(zipped_q, (2 * e), ins.esize));
                    m_ctx.writeElement(m_ctx.readQuadRegister((ins.m >> 1)), e, ins.esize, m_ctx.readElement(zipped_q, ((2 * e) + 1), ins.esize));
                }
                
            }
        } else {
            if ((ins.d == ins.m)) {
                m_ctx.writeDoubleRegister(ins.d, UNKNOWN_VALUE);
                m_ctx.writeDoubleRegister(ins.m, UNKNOWN_VALUE);
            } else {
                zipped_d = Concatenate(m_ctx.readDoubleRegister(ins.m), m_ctx.readDoubleRegister(ins.d), 64);
                for (e = 0; e < ((64 / ins.esize) - 1); ++e) {
                    m_ctx.writeElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize, m_ctx.readElement(zipped_d, (2 * e), ins.esize));
                    m_ctx.writeElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize, m_ctx.readElement(zipped_d, ((2 * e) + 1), ins.esize));
                }
                
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_vzip(const ARMInstruction &ins) {
    int zipped_q = 0;
    int e = 0;
    int zipped_d = 0;

    if (ConditionPassed()) {
        CheckAdvSIMDEnabled();
        if (ins.quadword_operation) {
            if ((ins.d == ins.m)) {
                m_ctx.writeQuadRegister((ins.d >> 1), UNKNOWN_VALUE);
                m_ctx.writeQuadRegister((ins.m >> 1), UNKNOWN_VALUE);
            } else {
                zipped_q = 0;
                for (e = 0; e < ((128 / ins.esize) - 1); ++e) {
                    m_ctx.writeElement(zipped_q, (2 * e), ins.esize, m_ctx.readElement(m_ctx.readQuadRegister((ins.d >> 1)), e, ins.esize));
                    m_ctx.writeElement(zipped_q, ((2 * e) + 1), ins.esize, m_ctx.readElement(m_ctx.readQuadRegister((ins.m >> 1)), e, ins.esize));
                }
                
                m_ctx.writeQuadRegister((ins.d >> 1), get_bits(zipped_q, 127, 0));
                m_ctx.writeQuadRegister((ins.m >> 1), get_bits(zipped_q, 255, 128));
            }
        } else {
            if ((ins.d == ins.m)) {
                m_ctx.writeDoubleRegister(ins.d, UNKNOWN_VALUE);
                m_ctx.writeDoubleRegister(ins.m, UNKNOWN_VALUE);
            } else {
                zipped_d = 0;
                for (e = 0; e < ((64 / ins.esize) - 1); ++e) {
                    m_ctx.writeElement(zipped_d, (2 * e), ins.esize, m_ctx.readElement(m_ctx.readDoubleRegister(ins.d), e, ins.esize));
                    m_ctx.writeElement(zipped_d, ((2 * e) + 1), ins.esize, m_ctx.readElement(m_ctx.readDoubleRegister(ins.m), e, ins.esize));
                }
                
                m_ctx.writeDoubleRegister(ins.d, get_bits(zipped_d, 63, 0));
                m_ctx.writeDoubleRegister(ins.m, get_bits(zipped_d, 127, 64));
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_wfe(const ARMInstruction &ins) {
    int HSRString = 0;

    if (ConditionPassed()) {
        if (EventRegistered()) {
            ClearEventRegister();
        } else {
            if ((((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp()) && (m_ctx.HCR.TWE == 1))) {
                HSRString = Zeros(25);
                set_bit(HSRString, 0, 1);
                WriteHSR(1, HSRString);
                TakeHypTrapException();
            } else {
                WaitForEvent();
            }
        }
    }
    return true;
}

bool ARMInterpreter::interpret_wfi(const ARMInstruction &ins) {
    int HSRString = 0;

    if (ConditionPassed()) {
        if ((((HaveVirtExt() && !IsSecure()) && !CurrentModeIsHyp()) && (m_ctx.HCR.TWI == 1))) {
            HSRString = Zeros(25);
            set_bit(HSRString, 0, 1);
            WriteHSR(1, HSRString);
            TakeHypTrapException();
        } else {
            WaitForInterrupt();
        }
    }
    return true;
}

bool ARMInterpreter::interpret_yield(const ARMInstruction &ins) {
    if (ConditionPassed()) {
        Hint_Yield();
    }
    return true;
}

