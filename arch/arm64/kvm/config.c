// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/kvm_host.h>
#include <asm/sysreg.h>

struct reg_bits_to_feat_map {
	u64		bits;

#define	NEVER_FGU	BIT(0)	/* Can trap, but never UNDEF */
#define	CALL_FUNC	BIT(1)	/* Needs to evaluate tons of crap */
	unsigned long	flags;

	union {
		struct {
			u8	regidx;
			u8	shift;
			u8	width;
			bool	sign;
			s8	lo_lim;
		};
		bool	(*match)(struct kvm *);
	};
};

#define __NEEDS_FEAT_3(m, f, id, fld, lim)		\
	{						\
		.bits	= (m),				\
		.flags = (f),				\
		.regidx	= IDREG_IDX(SYS_ ## id),	\
		.shift	= id ##_## fld ## _SHIFT,	\
		.width	= id ##_## fld ## _WIDTH,	\
		.sign	= id ##_## fld ## _SIGNED,	\
		.lo_lim	= id ##_## fld ##_## lim	\
	}

#define __NEEDS_FEAT_1(m, f, fun)			\
	{						\
		.bits	= (m),				\
		.flags = (f) | CALL_FUNC,		\
		.match = (fun),				\
	}

#define NEEDS_FEAT_FLAG(m, f, ...)			\
	CONCATENATE(__NEEDS_FEAT_, COUNT_ARGS(__VA_ARGS__))(m, f, __VA_ARGS__)

#define NEEDS_FEAT(m, ...)	NEEDS_FEAT_FLAG(m, 0, __VA_ARGS__)

#define FEAT_SPE		ID_AA64DFR0_EL1, PMSVer, IMP
#define FEAT_SPE_FnE		ID_AA64DFR0_EL1, PMSVer, V1P2
#define FEAT_BRBE		ID_AA64DFR0_EL1, BRBE, IMP
#define FEAT_TRC_SR		ID_AA64DFR0_EL1, TraceVer, IMP
#define FEAT_PMUv3		ID_AA64DFR0_EL1, PMUVer, IMP
#define FEAT_TRBE		ID_AA64DFR0_EL1, TraceBuffer, IMP
#define FEAT_DoubleLock		ID_AA64DFR0_EL1, DoubleLock, IMP
#define FEAT_TRF		ID_AA64DFR0_EL1, TraceFilt, IMP
#define FEAT_AA64EL1		ID_AA64PFR0_EL1, EL1, IMP
#define FEAT_AIE		ID_AA64MMFR3_EL1, AIE, IMP
#define FEAT_S2POE		ID_AA64MMFR3_EL1, S2POE, IMP
#define FEAT_S1POE		ID_AA64MMFR3_EL1, S1POE, IMP
#define FEAT_S1PIE		ID_AA64MMFR3_EL1, S1PIE, IMP
#define FEAT_THE		ID_AA64PFR1_EL1, THE, IMP
#define FEAT_SME		ID_AA64PFR1_EL1, SME, IMP
#define FEAT_GCS		ID_AA64PFR1_EL1, GCS, IMP
#define FEAT_LS64_ACCDATA	ID_AA64ISAR1_EL1, LS64, LS64_ACCDATA
#define FEAT_RAS		ID_AA64PFR0_EL1, RAS, IMP
#define FEAT_GICv3		ID_AA64PFR0_EL1, GIC, IMP
#define FEAT_LOR		ID_AA64MMFR1_EL1, LO, IMP
#define FEAT_SPEv1p5		ID_AA64DFR0_EL1, PMSVer, V1P5
#define FEAT_ATS1A		ID_AA64ISAR2_EL1, ATS1A, IMP
#define FEAT_SPECRES2		ID_AA64ISAR1_EL1, SPECRES, COSP_RCTX
#define FEAT_SPECRES		ID_AA64ISAR1_EL1, SPECRES, IMP
#define FEAT_TLBIRANGE		ID_AA64ISAR0_EL1, TLB, RANGE
#define FEAT_TLBIOS		ID_AA64ISAR0_EL1, TLB, OS
#define FEAT_PAN2		ID_AA64MMFR1_EL1, PAN, PAN2
#define FEAT_DPB2		ID_AA64ISAR1_EL1, DPB, DPB2
#define FEAT_AMUv1		ID_AA64PFR0_EL1, AMU, IMP

static bool feat_rasv1p1(struct kvm *kvm)
{
	return (kvm_has_feat(kvm, ID_AA64PFR0_EL1, RAS, V1P1) ||
		(kvm_has_feat_enum(kvm, ID_AA64PFR0_EL1, RAS, IMP) &&
		 kvm_has_feat(kvm, ID_AA64PFR1_EL1, RAS_frac, RASv1p1)));
}

static bool feat_csv2_2_csv2_1p2(struct kvm *kvm)
{
	return (kvm_has_feat(kvm,  ID_AA64PFR0_EL1, CSV2, CSV2_2) ||
		(kvm_has_feat(kvm, ID_AA64PFR1_EL1, CSV2_frac, CSV2_1p2) &&
		 kvm_has_feat_enum(kvm,  ID_AA64PFR0_EL1, CSV2, IMP)));
}

static bool feat_pauth(struct kvm *kvm)
{
	return kvm_has_pauth(kvm, PAuth);
}

static struct reg_bits_to_feat_map hfgrtr_feat_map[] = {
	NEEDS_FEAT(HFGxTR_EL2_nAMAIR2_EL1	|
		   HFGxTR_EL2_nMAIR2_EL1,
		   FEAT_AIE),
	NEEDS_FEAT(HFGxTR_EL2_nS2POR_EL1, FEAT_S2POE),
	NEEDS_FEAT(HFGxTR_EL2_nPOR_EL1		|
		   HFGxTR_EL2_nPOR_EL0,
		   FEAT_S1POE),
	NEEDS_FEAT(HFGxTR_EL2_nPIR_EL1		|
		   HFGxTR_EL2_nPIRE0_EL1,
		   FEAT_S1PIE),
	NEEDS_FEAT(HFGxTR_EL2_nRCWMASK_EL1, FEAT_THE),
	NEEDS_FEAT(HFGxTR_EL2_nTPIDR2_EL0	|
		   HFGxTR_EL2_nSMPRI_EL1,
		   FEAT_SME),
	NEEDS_FEAT(HFGxTR_EL2_nGCS_EL1		|
		   HFGxTR_EL2_nGCS_EL0,
		   FEAT_GCS),
	NEEDS_FEAT(HFGxTR_EL2_nACCDATA_EL1, FEAT_LS64_ACCDATA),
	NEEDS_FEAT(HFGxTR_EL2_ERXADDR_EL1	|
		   HFGxTR_EL2_ERXMISCn_EL1	|
		   HFGxTR_EL2_ERXSTATUS_EL1	|
		   HFGxTR_EL2_ERXCTLR_EL1	|
		   HFGxTR_EL2_ERXFR_EL1		|
		   HFGxTR_EL2_ERRSELR_EL1	|
		   HFGxTR_EL2_ERRIDR_EL1,
		   FEAT_RAS),
	NEEDS_FEAT(HFGxTR_EL2_ERXPFGCDN_EL1|
		   HFGxTR_EL2_ERXPFGCTL_EL1|
		   HFGxTR_EL2_ERXPFGF_EL1,
		   feat_rasv1p1),
	NEEDS_FEAT(HFGxTR_EL2_ICC_IGRPENn_EL1, FEAT_GICv3),
	NEEDS_FEAT(HFGxTR_EL2_SCXTNUM_EL0	|
		   HFGxTR_EL2_SCXTNUM_EL1,
		   feat_csv2_2_csv2_1p2),
	NEEDS_FEAT(HFGxTR_EL2_LORSA_EL1		|
		   HFGxTR_EL2_LORN_EL1		|
		   HFGxTR_EL2_LORID_EL1		|
		   HFGxTR_EL2_LOREA_EL1		|
		   HFGxTR_EL2_LORC_EL1,
		   FEAT_LOR),
	NEEDS_FEAT(HFGxTR_EL2_APIBKey		|
		   HFGxTR_EL2_APIAKey		|
		   HFGxTR_EL2_APGAKey		|
		   HFGxTR_EL2_APDBKey		|
		   HFGxTR_EL2_APDAKey,
		   feat_pauth),
	NEEDS_FEAT(HFGxTR_EL2_VBAR_EL1		|
		   HFGxTR_EL2_TTBR1_EL1		|
		   HFGxTR_EL2_TTBR0_EL1		|
		   HFGxTR_EL2_TPIDR_EL0		|
		   HFGxTR_EL2_TPIDRRO_EL0	|
		   HFGxTR_EL2_TPIDR_EL1		|
		   HFGxTR_EL2_TCR_EL1		|
		   HFGxTR_EL2_SCTLR_EL1		|
		   HFGxTR_EL2_REVIDR_EL1	|
		   HFGxTR_EL2_PAR_EL1		|
		   HFGxTR_EL2_MPIDR_EL1		|
		   HFGxTR_EL2_MIDR_EL1		|
		   HFGxTR_EL2_MAIR_EL1		|
		   HFGxTR_EL2_ISR_EL1		|
		   HFGxTR_EL2_FAR_EL1		|
		   HFGxTR_EL2_ESR_EL1		|
		   HFGxTR_EL2_DCZID_EL0		|
		   HFGxTR_EL2_CTR_EL0		|
		   HFGxTR_EL2_CSSELR_EL1	|
		   HFGxTR_EL2_CPACR_EL1		|
		   HFGxTR_EL2_CONTEXTIDR_EL1	|
		   HFGxTR_EL2_CLIDR_EL1		|
		   HFGxTR_EL2_CCSIDR_EL1	|
		   HFGxTR_EL2_AMAIR_EL1		|
		   HFGxTR_EL2_AIDR_EL1		|
		   HFGxTR_EL2_AFSR1_EL1		|
		   HFGxTR_EL2_AFSR0_EL1,
		   FEAT_AA64EL1),
};

static struct reg_bits_to_feat_map hfgwtr_feat_map[] = {
	NEEDS_FEAT(HFGxTR_EL2_nAMAIR2_EL1	|
		   HFGxTR_EL2_nMAIR2_EL1,
		   FEAT_AIE),
	NEEDS_FEAT(HFGxTR_EL2_nS2POR_EL1, FEAT_S2POE),
	NEEDS_FEAT(HFGxTR_EL2_nPOR_EL1		|
		   HFGxTR_EL2_nPOR_EL0,
		   FEAT_S1POE),
	NEEDS_FEAT(HFGxTR_EL2_nPIR_EL1		|
		   HFGxTR_EL2_nPIRE0_EL1,
		   FEAT_S1PIE),
	NEEDS_FEAT(HFGxTR_EL2_nRCWMASK_EL1, FEAT_THE),
	NEEDS_FEAT(HFGxTR_EL2_nTPIDR2_EL0	|
		   HFGxTR_EL2_nSMPRI_EL1,
		   FEAT_SME),
	NEEDS_FEAT(HFGxTR_EL2_nGCS_EL1		|
		   HFGxTR_EL2_nGCS_EL0,
		   FEAT_GCS),
	NEEDS_FEAT(HFGxTR_EL2_nACCDATA_EL1, FEAT_LS64_ACCDATA),
	NEEDS_FEAT(HFGxTR_EL2_ERXADDR_EL1	|
		   HFGxTR_EL2_ERXMISCn_EL1	|
		   HFGxTR_EL2_ERXSTATUS_EL1	|
		   HFGxTR_EL2_ERXCTLR_EL1	|
		   HFGxTR_EL2_ERRSELR_EL1,
		   FEAT_RAS),
	NEEDS_FEAT(HFGxTR_EL2_ERXPFGCDN_EL1	|
		   HFGxTR_EL2_ERXPFGCTL_EL1,
		   feat_rasv1p1),
	NEEDS_FEAT(HFGxTR_EL2_ICC_IGRPENn_EL1, FEAT_GICv3),
	NEEDS_FEAT(HFGxTR_EL2_SCXTNUM_EL0	|
		   HFGxTR_EL2_SCXTNUM_EL1,
		   feat_csv2_2_csv2_1p2),
	NEEDS_FEAT(HFGxTR_EL2_LORSA_EL1		|
		   HFGxTR_EL2_LORN_EL1		|
		   HFGxTR_EL2_LOREA_EL1		|
		   HFGxTR_EL2_LORC_EL1,
		   FEAT_LOR),
	NEEDS_FEAT(HFGxTR_EL2_APIBKey		|
		   HFGxTR_EL2_APIAKey		|
		   HFGxTR_EL2_APGAKey		|
		   HFGxTR_EL2_APDBKey		|
		   HFGxTR_EL2_APDAKey,
		   feat_pauth),
	NEEDS_FEAT(HFGxTR_EL2_VBAR_EL1		|
		   HFGxTR_EL2_TTBR1_EL1		|
		   HFGxTR_EL2_TTBR0_EL1		|
		   HFGxTR_EL2_TPIDR_EL0		|
		   HFGxTR_EL2_TPIDRRO_EL0	|
		   HFGxTR_EL2_TPIDR_EL1		|
		   HFGxTR_EL2_TCR_EL1		|
		   HFGxTR_EL2_SCTLR_EL1		|
		   HFGxTR_EL2_PAR_EL1		|
		   HFGxTR_EL2_MAIR_EL1		|
		   HFGxTR_EL2_FAR_EL1		|
		   HFGxTR_EL2_ESR_EL1		|
		   HFGxTR_EL2_CSSELR_EL1	|
		   HFGxTR_EL2_CPACR_EL1		|
		   HFGxTR_EL2_CONTEXTIDR_EL1	|
		   HFGxTR_EL2_AMAIR_EL1		|
		   HFGxTR_EL2_AFSR1_EL1		|
		   HFGxTR_EL2_AFSR0_EL1,
		   FEAT_AA64EL1),
};

static struct reg_bits_to_feat_map hdfgrtr_feat_map[] = {
	NEEDS_FEAT(HDFGRTR_EL2_PMBIDR_EL1	|
		   HDFGRTR_EL2_PMSLATFR_EL1	|
		   HDFGRTR_EL2_PMSIRR_EL1	|
		   HDFGRTR_EL2_PMSIDR_EL1	|
		   HDFGRTR_EL2_PMSICR_EL1	|
		   HDFGRTR_EL2_PMSFCR_EL1	|
		   HDFGRTR_EL2_PMSEVFR_EL1	|
		   HDFGRTR_EL2_PMSCR_EL1	|
		   HDFGRTR_EL2_PMBSR_EL1	|
		   HDFGRTR_EL2_PMBPTR_EL1	|
		   HDFGRTR_EL2_PMBLIMITR_EL1,
		   FEAT_SPE),
	NEEDS_FEAT(HDFGRTR_EL2_nPMSNEVFR_EL1, FEAT_SPE_FnE),
	NEEDS_FEAT(HDFGRTR_EL2_nBRBDATA		|
		   HDFGRTR_EL2_nBRBCTL		|
		   HDFGRTR_EL2_nBRBIDR,
		   FEAT_BRBE),
	NEEDS_FEAT(HDFGRTR_EL2_TRCVICTLR	|
		   HDFGRTR_EL2_TRCSTATR		|
		   HDFGRTR_EL2_TRCSSCSRn	|
		   HDFGRTR_EL2_TRCSEQSTR	|
		   HDFGRTR_EL2_TRCPRGCTLR	|
		   HDFGRTR_EL2_TRCOSLSR		|
		   HDFGRTR_EL2_TRCIMSPECn	|
		   HDFGRTR_EL2_TRCID		|
		   HDFGRTR_EL2_TRCCNTVRn	|
		   HDFGRTR_EL2_TRCCLAIM		|
		   HDFGRTR_EL2_TRCAUXCTLR	|
		   HDFGRTR_EL2_TRCAUTHSTATUS	|
		   HDFGRTR_EL2_TRC,
		   FEAT_TRC_SR),
	NEEDS_FEAT(HDFGRTR_EL2_PMCEIDn_EL0	|
		   HDFGRTR_EL2_PMUSERENR_EL0	|
		   HDFGRTR_EL2_PMMIR_EL1	|
		   HDFGRTR_EL2_PMSELR_EL0	|
		   HDFGRTR_EL2_PMOVS		|
		   HDFGRTR_EL2_PMINTEN		|
		   HDFGRTR_EL2_PMCNTEN		|
		   HDFGRTR_EL2_PMCCNTR_EL0	|
		   HDFGRTR_EL2_PMCCFILTR_EL0	|
		   HDFGRTR_EL2_PMEVTYPERn_EL0	|
		   HDFGRTR_EL2_PMEVCNTRn_EL0,
		   FEAT_PMUv3),
	NEEDS_FEAT(HDFGRTR_EL2_TRBTRG_EL1	|
		   HDFGRTR_EL2_TRBSR_EL1	|
		   HDFGRTR_EL2_TRBPTR_EL1	|
		   HDFGRTR_EL2_TRBMAR_EL1	|
		   HDFGRTR_EL2_TRBLIMITR_EL1	|
		   HDFGRTR_EL2_TRBIDR_EL1	|
		   HDFGRTR_EL2_TRBBASER_EL1,
		   FEAT_TRBE),
	NEEDS_FEAT_FLAG(HDFGRTR_EL2_OSDLR_EL1, NEVER_FGU,
			FEAT_DoubleLock),
	NEEDS_FEAT(HDFGRTR_EL2_OSECCR_EL1	|
		   HDFGRTR_EL2_OSLSR_EL1	|
		   HDFGRTR_EL2_DBGPRCR_EL1	|
		   HDFGRTR_EL2_DBGAUTHSTATUS_EL1|
		   HDFGRTR_EL2_DBGCLAIM		|
		   HDFGRTR_EL2_MDSCR_EL1	|
		   HDFGRTR_EL2_DBGWVRn_EL1	|
		   HDFGRTR_EL2_DBGWCRn_EL1	|
		   HDFGRTR_EL2_DBGBVRn_EL1	|
		   HDFGRTR_EL2_DBGBCRn_EL1,
		   FEAT_AA64EL1)
};

static struct reg_bits_to_feat_map hdfgwtr_feat_map[] = {
	NEEDS_FEAT(HDFGWTR_EL2_PMSLATFR_EL1	|
		   HDFGWTR_EL2_PMSIRR_EL1	|
		   HDFGWTR_EL2_PMSICR_EL1	|
		   HDFGWTR_EL2_PMSFCR_EL1	|
		   HDFGWTR_EL2_PMSEVFR_EL1	|
		   HDFGWTR_EL2_PMSCR_EL1	|
		   HDFGWTR_EL2_PMBSR_EL1	|
		   HDFGWTR_EL2_PMBPTR_EL1	|
		   HDFGWTR_EL2_PMBLIMITR_EL1,
		   FEAT_SPE),
	NEEDS_FEAT(HDFGWTR_EL2_nPMSNEVFR_EL1, FEAT_SPE_FnE),
	NEEDS_FEAT(HDFGWTR_EL2_nBRBDATA		|
		   HDFGWTR_EL2_nBRBCTL,
		   FEAT_BRBE),
	NEEDS_FEAT(HDFGWTR_EL2_TRCVICTLR	|
		   HDFGWTR_EL2_TRCSSCSRn	|
		   HDFGWTR_EL2_TRCSEQSTR	|
		   HDFGWTR_EL2_TRCPRGCTLR	|
		   HDFGWTR_EL2_TRCOSLAR		|
		   HDFGWTR_EL2_TRCIMSPECn	|
		   HDFGWTR_EL2_TRCCNTVRn	|
		   HDFGWTR_EL2_TRCCLAIM		|
		   HDFGWTR_EL2_TRCAUXCTLR	|
		   HDFGWTR_EL2_TRC,
		   FEAT_TRC_SR),
	NEEDS_FEAT(HDFGWTR_EL2_PMUSERENR_EL0	|
		   HDFGWTR_EL2_PMCR_EL0		|
		   HDFGWTR_EL2_PMSWINC_EL0	|
		   HDFGWTR_EL2_PMSELR_EL0	|
		   HDFGWTR_EL2_PMOVS		|
		   HDFGWTR_EL2_PMINTEN		|
		   HDFGWTR_EL2_PMCNTEN		|
		   HDFGWTR_EL2_PMCCNTR_EL0	|
		   HDFGWTR_EL2_PMCCFILTR_EL0	|
		   HDFGWTR_EL2_PMEVTYPERn_EL0	|
		   HDFGWTR_EL2_PMEVCNTRn_EL0,
		   FEAT_PMUv3),
	NEEDS_FEAT(HDFGWTR_EL2_TRBTRG_EL1	|
		   HDFGWTR_EL2_TRBSR_EL1	|
		   HDFGWTR_EL2_TRBPTR_EL1	|
		   HDFGWTR_EL2_TRBMAR_EL1	|
		   HDFGWTR_EL2_TRBLIMITR_EL1	|
		   HDFGWTR_EL2_TRBBASER_EL1,
		   FEAT_TRBE),
	NEEDS_FEAT_FLAG(HDFGWTR_EL2_OSDLR_EL1,
			NEVER_FGU, FEAT_DoubleLock),
	NEEDS_FEAT(HDFGWTR_EL2_OSECCR_EL1	|
		   HDFGWTR_EL2_OSLAR_EL1	|
		   HDFGWTR_EL2_DBGPRCR_EL1	|
		   HDFGWTR_EL2_DBGCLAIM		|
		   HDFGWTR_EL2_MDSCR_EL1	|
		   HDFGWTR_EL2_DBGWVRn_EL1	|
		   HDFGWTR_EL2_DBGWCRn_EL1	|
		   HDFGWTR_EL2_DBGBVRn_EL1	|
		   HDFGWTR_EL2_DBGBCRn_EL1,
		   FEAT_AA64EL1),
	NEEDS_FEAT(HDFGWTR_EL2_TRFCR_EL1, FEAT_TRF),
};


static struct reg_bits_to_feat_map hfgitr_feat_map[] = {
	NEEDS_FEAT(HFGITR_EL2_PSBCSYNC, FEAT_SPEv1p5),
	NEEDS_FEAT(HFGITR_EL2_ATS1E1A, FEAT_ATS1A),
	NEEDS_FEAT(HFGITR_EL2_COSPRCTX, FEAT_SPECRES2),
	NEEDS_FEAT(HFGITR_EL2_nGCSEPP		|
		   HFGITR_EL2_nGCSSTR_EL1	|
		   HFGITR_EL2_nGCSPUSHM_EL1,
		   FEAT_GCS),
	NEEDS_FEAT(HFGITR_EL2_nBRBIALL		|
		   HFGITR_EL2_nBRBINJ,
		   FEAT_BRBE),
	NEEDS_FEAT(HFGITR_EL2_CPPRCTX		|
		   HFGITR_EL2_DVPRCTX		|
		   HFGITR_EL2_CFPRCTX,
		   FEAT_SPECRES),
	NEEDS_FEAT(HFGITR_EL2_TLBIRVAALE1	|
		   HFGITR_EL2_TLBIRVALE1	|
		   HFGITR_EL2_TLBIRVAAE1	|
		   HFGITR_EL2_TLBIRVAE1		|
		   HFGITR_EL2_TLBIRVAALE1IS	|
		   HFGITR_EL2_TLBIRVALE1IS	|
		   HFGITR_EL2_TLBIRVAAE1IS	|
		   HFGITR_EL2_TLBIRVAE1IS	|
		   HFGITR_EL2_TLBIRVAALE1OS	|
		   HFGITR_EL2_TLBIRVALE1OS	|
		   HFGITR_EL2_TLBIRVAAE1OS	|
		   HFGITR_EL2_TLBIRVAE1OS,
		   FEAT_TLBIRANGE),
	NEEDS_FEAT(HFGITR_EL2_TLBIVAALE1OS	|
		   HFGITR_EL2_TLBIVALE1OS	|
		   HFGITR_EL2_TLBIVAAE1OS	|
		   HFGITR_EL2_TLBIASIDE1OS	|
		   HFGITR_EL2_TLBIVAE1OS	|
		   HFGITR_EL2_TLBIVMALLE1OS,
		   FEAT_TLBIOS),
	NEEDS_FEAT(HFGITR_EL2_ATS1E1WP		|
		   HFGITR_EL2_ATS1E1RP,
		   FEAT_PAN2),
	NEEDS_FEAT(HFGITR_EL2_DCCVADP, FEAT_DPB2),
	NEEDS_FEAT(HFGITR_EL2_DCCVAC		|
		   HFGITR_EL2_SVC_EL1		|
		   HFGITR_EL2_SVC_EL0		|
		   HFGITR_EL2_ERET		|
		   HFGITR_EL2_TLBIVAALE1	|
		   HFGITR_EL2_TLBIVALE1		|
		   HFGITR_EL2_TLBIVAAE1		|
		   HFGITR_EL2_TLBIASIDE1	|
		   HFGITR_EL2_TLBIVAE1		|
		   HFGITR_EL2_TLBIVMALLE1	|
		   HFGITR_EL2_TLBIVAALE1IS	|
		   HFGITR_EL2_TLBIVALE1IS	|
		   HFGITR_EL2_TLBIVAAE1IS	|
		   HFGITR_EL2_TLBIASIDE1IS	|
		   HFGITR_EL2_TLBIVAE1IS	|
		   HFGITR_EL2_TLBIVMALLE1IS	|
		   HFGITR_EL2_ATS1E0W		|
		   HFGITR_EL2_ATS1E0R		|
		   HFGITR_EL2_ATS1E1W		|
		   HFGITR_EL2_ATS1E1R		|
		   HFGITR_EL2_DCZVA		|
		   HFGITR_EL2_DCCIVAC		|
		   HFGITR_EL2_DCCVAP		|
		   HFGITR_EL2_DCCVAU		|
		   HFGITR_EL2_DCCISW		|
		   HFGITR_EL2_DCCSW		|
		   HFGITR_EL2_DCISW		|
		   HFGITR_EL2_DCIVAC		|
		   HFGITR_EL2_ICIVAU		|
		   HFGITR_EL2_ICIALLU		|
		   HFGITR_EL2_ICIALLUIS,
		   FEAT_AA64EL1),
};

static struct reg_bits_to_feat_map hafgrtr_feat_map[] = {
	NEEDS_FEAT(HAFGRTR_EL2_AMEVTYPER115_EL0	|
		   HAFGRTR_EL2_AMEVTYPER114_EL0	|
		   HAFGRTR_EL2_AMEVTYPER113_EL0	|
		   HAFGRTR_EL2_AMEVTYPER112_EL0	|
		   HAFGRTR_EL2_AMEVTYPER111_EL0	|
		   HAFGRTR_EL2_AMEVTYPER110_EL0	|
		   HAFGRTR_EL2_AMEVTYPER19_EL0	|
		   HAFGRTR_EL2_AMEVTYPER18_EL0	|
		   HAFGRTR_EL2_AMEVTYPER17_EL0	|
		   HAFGRTR_EL2_AMEVTYPER16_EL0	|
		   HAFGRTR_EL2_AMEVTYPER15_EL0	|
		   HAFGRTR_EL2_AMEVTYPER14_EL0	|
		   HAFGRTR_EL2_AMEVTYPER13_EL0	|
		   HAFGRTR_EL2_AMEVTYPER12_EL0	|
		   HAFGRTR_EL2_AMEVTYPER11_EL0	|
		   HAFGRTR_EL2_AMEVTYPER10_EL0	|
		   HAFGRTR_EL2_AMEVCNTR115_EL0	|
		   HAFGRTR_EL2_AMEVCNTR114_EL0	|
		   HAFGRTR_EL2_AMEVCNTR113_EL0	|
		   HAFGRTR_EL2_AMEVCNTR112_EL0	|
		   HAFGRTR_EL2_AMEVCNTR111_EL0	|
		   HAFGRTR_EL2_AMEVCNTR110_EL0	|
		   HAFGRTR_EL2_AMEVCNTR19_EL0	|
		   HAFGRTR_EL2_AMEVCNTR18_EL0	|
		   HAFGRTR_EL2_AMEVCNTR17_EL0	|
		   HAFGRTR_EL2_AMEVCNTR16_EL0	|
		   HAFGRTR_EL2_AMEVCNTR15_EL0	|
		   HAFGRTR_EL2_AMEVCNTR14_EL0	|
		   HAFGRTR_EL2_AMEVCNTR13_EL0	|
		   HAFGRTR_EL2_AMEVCNTR12_EL0	|
		   HAFGRTR_EL2_AMEVCNTR11_EL0	|
		   HAFGRTR_EL2_AMEVCNTR10_EL0	|
		   HAFGRTR_EL2_AMCNTEN1		|
		   HAFGRTR_EL2_AMCNTEN0		|
		   HAFGRTR_EL2_AMEVCNTR03_EL0	|
		   HAFGRTR_EL2_AMEVCNTR02_EL0	|
		   HAFGRTR_EL2_AMEVCNTR01_EL0	|
		   HAFGRTR_EL2_AMEVCNTR00_EL0,
		   FEAT_AMUv1),
};

static void __init check_feat_map(struct reg_bits_to_feat_map *map,
				  int map_size, u64 res0, const char *str)
{
	u64 mask = 0;

	for (int i = 0; i < map_size; i++)
		mask |= map[i].bits;

	if (mask != ~res0)
		kvm_err("Undefined %s behaviour, bits %016llx\n",
			str, mask ^ ~res0);
}

void __init check_feature_map(void)
{
	check_feat_map(hfgrtr_feat_map, ARRAY_SIZE(hfgrtr_feat_map),
		       hfgrtr_masks.res0, hfgrtr_masks.str);
	check_feat_map(hfgwtr_feat_map, ARRAY_SIZE(hfgwtr_feat_map),
		       hfgwtr_masks.res0, hfgwtr_masks.str);
	check_feat_map(hfgitr_feat_map, ARRAY_SIZE(hfgitr_feat_map),
		       hfgitr_masks.res0, hfgitr_masks.str);
	check_feat_map(hdfgrtr_feat_map, ARRAY_SIZE(hdfgrtr_feat_map),
		       hdfgrtr_masks.res0, hdfgrtr_masks.str);
	check_feat_map(hdfgwtr_feat_map, ARRAY_SIZE(hdfgwtr_feat_map),
		       hdfgwtr_masks.res0, hdfgwtr_masks.str);
	check_feat_map(hafgrtr_feat_map, ARRAY_SIZE(hafgrtr_feat_map),
		       hafgrtr_masks.res0, hafgrtr_masks.str);
}

static bool idreg_feat_match(struct kvm *kvm, struct reg_bits_to_feat_map *map)
{
	u64 regval = kvm->arch.id_regs[map->regidx];
	u64 regfld = (regval >> map->shift) & GENMASK(map->width - 1, 0);

	if (map->sign) {
		s64 sfld = sign_extend64(regfld, map->width - 1);
		s64 slim = sign_extend64(map->lo_lim, map->width - 1);
		return sfld >= slim;
	} else {
		return regfld >= map->lo_lim;
	}
}

static u64 __compute_unsupported_bits(struct kvm *kvm,
				      struct reg_bits_to_feat_map *map,
				      int map_size, unsigned long filter_out)
{
	u64 val = 0;

	for (int i = 0; i < map_size; i++) {
		bool match;

		if (map[i].flags & filter_out)
			continue;

		if (map[i].flags & CALL_FUNC)
			match = map[i].match(kvm);
		else
			match = idreg_feat_match(kvm, &map[i]);

		if (!match)
			val |= map[i].bits;
	}

	return val;
}

void compute_fgu(struct kvm *kvm, enum fgt_group_id fgt)
{
	u64 val = 0;

	switch (fgt) {
	case HFGxTR_GROUP:
		val |= __compute_unsupported_bits(kvm, hfgrtr_feat_map,
						  ARRAY_SIZE(hfgrtr_feat_map),
						  NEVER_FGU);
		val |= __compute_unsupported_bits(kvm, hfgwtr_feat_map,
						  ARRAY_SIZE(hfgwtr_feat_map),
						  NEVER_FGU);
		break;
	case HFGITR_GROUP:
		val |= __compute_unsupported_bits(kvm, hfgitr_feat_map,
						  ARRAY_SIZE(hfgitr_feat_map),
						  NEVER_FGU);
		break;
	case HDFGRTR_GROUP:
		val |= __compute_unsupported_bits(kvm, hdfgrtr_feat_map,
						  ARRAY_SIZE(hdfgrtr_feat_map),
						  NEVER_FGU);
		val |= __compute_unsupported_bits(kvm, hdfgwtr_feat_map,
						  ARRAY_SIZE(hdfgwtr_feat_map),
						  NEVER_FGU);
		break;
	case HAFGRTR_GROUP:
		val |= __compute_unsupported_bits(kvm, hafgrtr_feat_map,
						  ARRAY_SIZE(hafgrtr_feat_map),
						  NEVER_FGU);
		break;
	default:
		BUG();
	}

	kvm->arch.fgu[fgt] = val;
}
