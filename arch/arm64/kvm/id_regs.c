// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 - Google LLC
 * Author: Jing Zhang <jingzhangos@google.com>
 *
 * Moved from arch/arm64/kvm/sys_regs.c
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/bitfield.h>
#include <linux/bsearch.h>
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>
#include <asm/kvm_nested.h>

#include "sys_regs.h"

/**
 * arm64_check_features() - Check if a feature register value constitutes
 * a subset of features indicated by the idreg's KVM sanitised limit.
 *
 * This function will check if each feature field of @val is the "safe" value
 * against idreg's KVM sanitised limit return from reset() callback.
 * If a field value in @val is the same as the one in limit, it is always
 * considered the safe value regardless For register fields that are not in
 * writable, only the value in limit is considered the safe value.
 *
 * Return: 0 if all the fields are safe. Otherwise, return negative errno.
 */
static int arm64_check_features(struct kvm_vcpu *vcpu,
				const struct sys_reg_desc *rd,
				u64 val)
{
	const struct arm64_ftr_reg *ftr_reg;
	const struct arm64_ftr_bits *ftrp = NULL;
	u32 id = reg_to_encoding(rd);
	u64 writable_mask = rd->val;
	u64 limit = 0;
	u64 mask = 0;

	/* For hidden and unallocated idregs without reset, only val = 0 is allowed. */
	if (rd->reset) {
		limit = rd->reset(vcpu, rd);
		ftr_reg = get_arm64_ftr_reg(id);
		if (!ftr_reg)
			return -EINVAL;
		ftrp = ftr_reg->ftr_bits;
	}

	for (; ftrp && ftrp->width; ftrp++) {
		s64 f_val, f_lim, safe_val;
		u64 ftr_mask;

		ftr_mask = arm64_ftr_mask(ftrp);
		if ((ftr_mask & writable_mask) != ftr_mask)
			continue;

		f_val = arm64_ftr_value(ftrp, val);
		f_lim = arm64_ftr_value(ftrp, limit);
		mask |= ftr_mask;

		if (f_val == f_lim)
			safe_val = f_val;
		else
			safe_val = arm64_ftr_safe_value(ftrp, f_val, f_lim);

		if (safe_val != f_val)
			return -E2BIG;
	}

	/* For fields that are not writable, values in limit are the safe values. */
	if ((val & ~mask) != (limit & ~mask))
		return -E2BIG;

	return 0;
}

static u8 vcpu_pmuver(const struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_has_pmu(vcpu))
		return FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer),
				 IDREG(vcpu->kvm, SYS_ID_AA64DFR0_EL1));
	else if (test_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags))
		return ID_AA64DFR0_EL1_PMUVer_IMP_DEF;

	return 0;
}

static u8 perfmon_to_pmuver(u8 perfmon)
{
	switch (perfmon) {
	case ID_DFR0_EL1_PerfMon_PMUv3:
		return ID_AA64DFR0_EL1_PMUVer_IMP;
	case ID_DFR0_EL1_PerfMon_IMPDEF:
		return ID_AA64DFR0_EL1_PMUVer_IMP_DEF;
	default:
		/* Anything ARMv8.1+ and NI have the same value. For now. */
		return perfmon;
	}
}

static u8 pmuver_to_perfmon(u8 pmuver)
{
	switch (pmuver) {
	case ID_AA64DFR0_EL1_PMUVer_IMP:
		return ID_DFR0_EL1_PerfMon_PMUv3;
	case ID_AA64DFR0_EL1_PMUVer_IMP_DEF:
		return ID_DFR0_EL1_PerfMon_IMPDEF;
	default:
		/* Anything ARMv8.1+ and NI have the same value. For now. */
		return pmuver;
	}
}

static u64 general_read_kvm_sanitised_reg(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd)
{
	return read_sanitised_ftr_reg(reg_to_encoding(rd));
}

u64 kvm_arm_read_id_reg(const struct kvm_vcpu *vcpu, u32 id)
{
	u64 val = IDREG(vcpu->kvm, id);

	switch (id) {
	case SYS_ID_AA64PFR0_EL1:
		if (!vcpu_has_sve(vcpu))
			val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_SVE);
		if (kvm_vgic_global_state.type == VGIC_V3) {
			val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_GIC);
			val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_GIC), 1);
		}
		break;
	case SYS_ID_AA64PFR1_EL1:
		if (!kvm_has_mte(vcpu->kvm))
			val &= ~ARM64_FEATURE_MASK(ID_AA64PFR1_EL1_MTE);

		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR1_EL1_SME);
		break;
	case SYS_ID_AA64ISAR1_EL1:
		if (!vcpu_has_ptrauth(vcpu))
			val &= ~(ARM64_FEATURE_MASK(ID_AA64ISAR1_EL1_APA) |
				 ARM64_FEATURE_MASK(ID_AA64ISAR1_EL1_API) |
				 ARM64_FEATURE_MASK(ID_AA64ISAR1_EL1_GPA) |
				 ARM64_FEATURE_MASK(ID_AA64ISAR1_EL1_GPI));
		break;
	case SYS_ID_AA64ISAR2_EL1:
		if (!vcpu_has_ptrauth(vcpu))
			val &= ~(ARM64_FEATURE_MASK(ID_AA64ISAR2_EL1_APA3) |
				 ARM64_FEATURE_MASK(ID_AA64ISAR2_EL1_GPA3));
		if (!cpus_have_final_cap(ARM64_HAS_WFXT))
			val &= ~ARM64_FEATURE_MASK(ID_AA64ISAR2_EL1_WFxT);
		break;
	case SYS_ID_AA64DFR0_EL1:
		/* Set PMUver to the required version */
		val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer),
				  vcpu_pmuver(vcpu));
		break;
	case SYS_ID_DFR0_EL1:
		val &= ~ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon),
				  pmuver_to_perfmon(vcpu_pmuver(vcpu)));
		break;
	case SYS_ID_AA64MMFR2_EL1:
		val &= ~ID_AA64MMFR2_EL1_CCIDX_MASK;
		break;
	case SYS_ID_MMFR4_EL1:
		val &= ~ARM64_FEATURE_MASK(ID_MMFR4_EL1_CCIDX);
		break;
	}

	return val;
}

static u64 read_id_reg(const struct kvm_vcpu *vcpu, struct sys_reg_desc const *r)
{
	if (sysreg_visible_as_raz(vcpu, r))
		return 0;

	return kvm_arm_read_id_reg(vcpu, reg_to_encoding(r));
}

/* cpufeature ID register access trap handlers */

static bool access_id_reg(struct kvm_vcpu *vcpu,
			  struct sys_reg_params *p,
			  const struct sys_reg_desc *r)
{
	if (p->is_write)
		return write_to_read_only(vcpu, p, r);

	p->regval = read_id_reg(vcpu, r);
	if (vcpu_has_nv(vcpu))
		access_nested_id_reg(vcpu, p, r);

	return true;
}

/*
 * cpufeature ID register user accessors
 *
 * For now, these registers are immutable for userspace, so no values
 * are stored, and for set_id_reg() we don't allow the effective value
 * to be changed.
 */
static int get_id_reg(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd,
		      u64 *val)
{
	*val = read_id_reg(vcpu, rd);
	return 0;
}

static int set_id_reg(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd,
		      u64 val)
{
	u32 id = reg_to_encoding(rd);
	int ret;

	ret = arm64_check_features(vcpu, rd, val);
	if (ret)
		return ret;

	IDREG(vcpu->kvm, id) = val;

	return 0;
}

static unsigned int id_visibility(const struct kvm_vcpu *vcpu,
				  const struct sys_reg_desc *r)
{
	u32 id = reg_to_encoding(r);

	switch (id) {
	case SYS_ID_AA64ZFR0_EL1:
		if (!vcpu_has_sve(vcpu))
			return REG_RAZ;
		break;
	}

	return 0;
}

static unsigned int aa32_id_visibility(const struct kvm_vcpu *vcpu,
				       const struct sys_reg_desc *r)
{
	/*
	 * AArch32 ID registers are UNKNOWN if AArch32 isn't implemented at any
	 * EL. Promote to RAZ/WI in order to guarantee consistency between
	 * systems.
	 */
	if (!kvm_supports_32bit_el0())
		return REG_RAZ | REG_USER_WI;

	return id_visibility(vcpu, r);
}

static u64 read_sanitised_id_aa64pfr0_el1(struct kvm_vcpu *vcpu,
					  const struct sys_reg_desc *rd)
{
	u64 val;
	u32 id = reg_to_encoding(rd);

	val = read_sanitised_ftr_reg(id);
	/*
	 * The default is to expose CSV2 == 1 if the HW isn't affected.
	 * Although this is a per-CPU feature, we make it global because
	 * asymmetric systems are just a nuisance.
	 *
	 * Userspace can override this as long as it doesn't promise
	 * the impossible.
	 */
	if (arm64_get_spectre_v2_state() == SPECTRE_UNAFFECTED) {
		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV2);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV2), 1);
	}
	if (arm64_get_meltdown_state() == SPECTRE_UNAFFECTED) {
		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV3);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV3), 1);
	}

	val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_AMU);

	return val;
}

static int set_id_aa64pfr0_el1(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 val)
{
	u8 csv2, csv3;

	/*
	 * Allow AA64PFR0_EL1.CSV2 to be set from userspace as long as
	 * it doesn't promise more than what is actually provided (the
	 * guest could otherwise be covered in ectoplasmic residue).
	 */
	csv2 = cpuid_feature_extract_unsigned_field(val, ID_AA64PFR0_EL1_CSV2_SHIFT);
	if (csv2 > 1 || (csv2 && arm64_get_spectre_v2_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	/* Same thing for CSV3 */
	csv3 = cpuid_feature_extract_unsigned_field(val, ID_AA64PFR0_EL1_CSV3_SHIFT);
	if (csv3 > 1 || (csv3 && arm64_get_meltdown_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	return set_id_reg(vcpu, rd, val);
}

static u64 read_sanitised_id_aa64dfr0_el1(struct kvm_vcpu *vcpu,
					  const struct sys_reg_desc *rd)
{
	u64 val;
	u32 id = reg_to_encoding(rd);

	val = read_sanitised_ftr_reg(id);
	/* Limit debug to ARMv8.0 */
	val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_DebugVer);
	val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_DebugVer), 6);
	/*
	 * Initialise the default PMUver before there is a chance to
	 * create an actual PMU.
	 */
	val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer);
	val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer),
			  kvm_arm_pmu_get_pmuver_limit());
	/* Hide SPE from guests */
	val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMSVer);

	return val;
}

static int set_id_aa64dfr0_el1(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 val)
{
	u8 pmuver, host_pmuver;
	bool valid_pmu;
	int ret;

	host_pmuver = kvm_arm_pmu_get_pmuver_limit();

	/*
	 * Allow AA64DFR0_EL1.PMUver to be set from userspace as long
	 * as it doesn't promise more than what the HW gives us. We
	 * allow an IMPDEF PMU though, only if no PMU is supported
	 * (KVM backward compatibility handling).
	 */
	pmuver = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer), val);
	if ((pmuver != ID_AA64DFR0_EL1_PMUVer_IMP_DEF && pmuver > host_pmuver))
		return -EINVAL;

	valid_pmu = (pmuver != 0 && pmuver != ID_AA64DFR0_EL1_PMUVer_IMP_DEF);

	/* Make sure view register and PMU support do match */
	if (kvm_vcpu_has_pmu(vcpu) != valid_pmu)
		return -EINVAL;

	if (!valid_pmu) {
		/*
		 * Ignore the PMUVer filed in @val. The PMUVer would be determined
		 * by arch flags bit KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU,
		 */
		pmuver = FIELD_GET(ID_AA64DFR0_EL1_PMUVer_MASK, read_id_reg(vcpu, rd));
		val &= ~ID_AA64DFR0_EL1_PMUVer_MASK;
		val |= FIELD_PREP(ID_AA64DFR0_EL1_PMUVer_MASK, pmuver);
	}

	mutex_lock(&vcpu->kvm->arch.config_lock);

	ret = set_id_reg(vcpu, rd, val);
	if (ret) {
		mutex_unlock(&vcpu->kvm->arch.config_lock);
		return ret;
	}

	IDREG(vcpu->kvm, SYS_ID_DFR0_EL1) &= ~ID_DFR0_EL1_PerfMon_MASK;
	IDREG(vcpu->kvm, SYS_ID_DFR0_EL1) |= FIELD_PREP(ID_DFR0_EL1_PerfMon_MASK,
							pmuver_to_perfmon(pmuver));

	if (!valid_pmu)
		assign_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags,
			   pmuver == ID_AA64DFR0_EL1_PMUVer_IMP_DEF);

	mutex_unlock(&vcpu->kvm->arch.config_lock);

	return 0;
}

static u64 read_sanitised_id_dfr0_el1(struct kvm_vcpu *vcpu,
				      const struct sys_reg_desc *rd)
{
	u64 val;
	u32 id = reg_to_encoding(rd);

	val = read_sanitised_ftr_reg(id);
	/*
	 * Initialise the default PMUver before there is a chance to
	 * create an actual PMU.
	 */
	val &= ~ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon);
	val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon), kvm_arm_pmu_get_pmuver_limit());

	return val;
}

static int set_id_dfr0_el1(struct kvm_vcpu *vcpu,
			   const struct sys_reg_desc *rd,
			   u64 val)
{
	u8 perfmon, host_perfmon;
	bool valid_pmu;
	int ret;

	host_perfmon = pmuver_to_perfmon(kvm_arm_pmu_get_pmuver_limit());

	/*
	 * Allow DFR0_EL1.PerfMon to be set from userspace as long as
	 * it doesn't promise more than what the HW gives us on the
	 * AArch64 side (as everything is emulated with that), and
	 * that this is a PMUv3.
	 */
	perfmon = FIELD_GET(ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon), val);
	if ((perfmon != ID_DFR0_EL1_PerfMon_IMPDEF && perfmon > host_perfmon) ||
	    (perfmon != 0 && perfmon < ID_DFR0_EL1_PerfMon_PMUv3))
		return -EINVAL;

	valid_pmu = (perfmon != 0 && perfmon != ID_DFR0_EL1_PerfMon_IMPDEF);

	/* Make sure view register and PMU support do match */
	if (kvm_vcpu_has_pmu(vcpu) != valid_pmu)
		return -EINVAL;

	if (!valid_pmu) {
		/*
		 * Ignore the PerfMon filed in @val. The PerfMon would be determined
		 * by arch flags bit KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU,
		 */
		perfmon = FIELD_GET(ID_DFR0_EL1_PerfMon_MASK, read_id_reg(vcpu, rd));
		val &= ~ID_DFR0_EL1_PerfMon_MASK;
		val |= FIELD_PREP(ID_DFR0_EL1_PerfMon_MASK, perfmon);
	}

	mutex_lock(&vcpu->kvm->arch.config_lock);

	ret = set_id_reg(vcpu, rd, val);
	if (ret) {
		mutex_unlock(&vcpu->kvm->arch.config_lock);
		return ret;
	}

	IDREG(vcpu->kvm, SYS_ID_AA64DFR0_EL1) &= ~ID_AA64DFR0_EL1_PMUVer_MASK;
	IDREG(vcpu->kvm, SYS_ID_AA64DFR0_EL1) |= FIELD_PREP(ID_AA64DFR0_EL1_PMUVer_MASK,
							    perfmon_to_pmuver(perfmon));

	if (!valid_pmu)
		assign_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags,
			   perfmon == ID_DFR0_EL1_PerfMon_IMPDEF);

	mutex_unlock(&vcpu->kvm->arch.config_lock);

	return 0;
}

/*
 * Since reset() callback and field val are not used for idregs, they will be
 * used for specific purposes for idregs.
 * The reset() would return KVM sanitised register value. The value would be the
 * same as the host kernel sanitised value if there is no KVM sanitisation.
 * The val would be used as a mask indicating writable fields for the idreg.
 * Only bits with 1 are writable from userspace. This mask might not be
 * necessary in the future whenever all ID registers are enabled as writable
 * from userspace.
 */

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define ID_SANITISED(name) {			\
	SYS_DESC(SYS_##name),			\
	.access	= access_id_reg,		\
	.get_user = get_id_reg,			\
	.set_user = set_id_reg,			\
	.visibility = id_visibility,		\
	.reset = general_read_kvm_sanitised_reg,\
	.val = 0,				\
}

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define AA32_ID_SANITISED(name) {		\
	SYS_DESC(SYS_##name),			\
	.access	= access_id_reg,		\
	.get_user = get_id_reg,			\
	.set_user = set_id_reg,			\
	.visibility = aa32_id_visibility,	\
	.reset = general_read_kvm_sanitised_reg,\
	.val = 0,				\
}

/*
 * sys_reg_desc initialiser for architecturally unallocated cpufeature ID
 * register with encoding Op0=3, Op1=0, CRn=0, CRm=crm, Op2=op2
 * (1 <= crm < 8, 0 <= Op2 < 8).
 */
#define ID_UNALLOCATED(crm, op2) {			\
	Op0(3), Op1(0), CRn(0), CRm(crm), Op2(op2),	\
	.access = access_id_reg,			\
	.get_user = get_id_reg,				\
	.set_user = set_id_reg,				\
	.visibility = raz_visibility,			\
	.reset = NULL,					\
	.val = 0,					\
}

/*
 * sys_reg_desc initialiser for known ID registers that we hide from guests.
 * For now, these are exposed just like unallocated ID regs: they appear
 * RAZ for the guest.
 */
#define ID_HIDDEN(name) {			\
	SYS_DESC(SYS_##name),			\
	.access = access_id_reg,		\
	.get_user = get_id_reg,			\
	.set_user = set_id_reg,			\
	.visibility = raz_visibility,		\
	.reset = NULL,				\
	.val = 0,				\
}

const struct sys_reg_desc id_reg_descs[KVM_ARM_ID_REG_NUM] = {
	/*
	 * ID regs: all ID_SANITISED() entries here must have corresponding
	 * entries in arm64_ftr_regs[].
	 */

	/* AArch64 mappings of the AArch32 ID registers */
	/* CRm=1 */
	AA32_ID_SANITISED(ID_PFR0_EL1),
	AA32_ID_SANITISED(ID_PFR1_EL1),
	{ SYS_DESC(SYS_ID_DFR0_EL1),
	  .access = access_id_reg,
	  .get_user = get_id_reg,
	  .set_user = set_id_dfr0_el1,
	  .visibility = aa32_id_visibility,
	  .reset = read_sanitised_id_dfr0_el1,
	  .val = ID_DFR0_EL1_PerfMon_MASK, },
	ID_HIDDEN(ID_AFR0_EL1),
	AA32_ID_SANITISED(ID_MMFR0_EL1),
	AA32_ID_SANITISED(ID_MMFR1_EL1),
	AA32_ID_SANITISED(ID_MMFR2_EL1),
	AA32_ID_SANITISED(ID_MMFR3_EL1),

	/* CRm=2 */
	AA32_ID_SANITISED(ID_ISAR0_EL1),
	AA32_ID_SANITISED(ID_ISAR1_EL1),
	AA32_ID_SANITISED(ID_ISAR2_EL1),
	AA32_ID_SANITISED(ID_ISAR3_EL1),
	AA32_ID_SANITISED(ID_ISAR4_EL1),
	AA32_ID_SANITISED(ID_ISAR5_EL1),
	AA32_ID_SANITISED(ID_MMFR4_EL1),
	AA32_ID_SANITISED(ID_ISAR6_EL1),

	/* CRm=3 */
	AA32_ID_SANITISED(MVFR0_EL1),
	AA32_ID_SANITISED(MVFR1_EL1),
	AA32_ID_SANITISED(MVFR2_EL1),
	ID_UNALLOCATED(3, 3),
	AA32_ID_SANITISED(ID_PFR2_EL1),
	ID_HIDDEN(ID_DFR1_EL1),
	AA32_ID_SANITISED(ID_MMFR5_EL1),
	ID_UNALLOCATED(3, 7),

	/* AArch64 ID registers */
	/* CRm=4 */
	{ SYS_DESC(SYS_ID_AA64PFR0_EL1),
	  .access = access_id_reg,
	  .get_user = get_id_reg,
	  .set_user = set_id_aa64pfr0_el1,
	  .reset = read_sanitised_id_aa64pfr0_el1,
	  .val = ID_AA64PFR0_EL1_CSV2_MASK | ID_AA64PFR0_EL1_CSV3_MASK, },
	ID_SANITISED(ID_AA64PFR1_EL1),
	ID_UNALLOCATED(4, 2),
	ID_UNALLOCATED(4, 3),
	ID_SANITISED(ID_AA64ZFR0_EL1),
	ID_HIDDEN(ID_AA64SMFR0_EL1),
	ID_UNALLOCATED(4, 6),
	ID_UNALLOCATED(4, 7),

	/* CRm=5 */
	{ SYS_DESC(SYS_ID_AA64DFR0_EL1),
	  .access = access_id_reg,
	  .get_user = get_id_reg,
	  .set_user = set_id_aa64dfr0_el1,
	  .reset = read_sanitised_id_aa64dfr0_el1,
	  .val = ID_AA64DFR0_EL1_PMUVer_MASK, },
	ID_SANITISED(ID_AA64DFR1_EL1),
	ID_UNALLOCATED(5, 2),
	ID_UNALLOCATED(5, 3),
	ID_HIDDEN(ID_AA64AFR0_EL1),
	ID_HIDDEN(ID_AA64AFR1_EL1),
	ID_UNALLOCATED(5, 6),
	ID_UNALLOCATED(5, 7),

	/* CRm=6 */
	ID_SANITISED(ID_AA64ISAR0_EL1),
	ID_SANITISED(ID_AA64ISAR1_EL1),
	ID_SANITISED(ID_AA64ISAR2_EL1),
	ID_UNALLOCATED(6, 3),
	ID_UNALLOCATED(6, 4),
	ID_UNALLOCATED(6, 5),
	ID_UNALLOCATED(6, 6),
	ID_UNALLOCATED(6, 7),

	/* CRm=7 */
	ID_SANITISED(ID_AA64MMFR0_EL1),
	ID_SANITISED(ID_AA64MMFR1_EL1),
	ID_SANITISED(ID_AA64MMFR2_EL1),
	ID_UNALLOCATED(7, 3),
	ID_UNALLOCATED(7, 4),
	ID_UNALLOCATED(7, 5),
	ID_UNALLOCATED(7, 6),
	ID_UNALLOCATED(7, 7),
};

/**
 * emulate_id_reg - Emulate a guest access to an AArch64 CPU ID feature register
 * @vcpu: The VCPU pointer
 * @params: Decoded system register parameters
 *
 * Return: true if the ID register access was successful, false otherwise.
 */
int emulate_id_reg(struct kvm_vcpu *vcpu, struct sys_reg_params *params)
{
	const struct sys_reg_desc *r;

	r = find_reg(params, id_reg_descs, ARRAY_SIZE(id_reg_descs));

	if (likely(r)) {
		perform_access(vcpu, params, r);
	} else {
		print_sys_reg_msg(params,
				  "Unsupported guest id_reg access at: %lx [%08lx]\n",
				  *vcpu_pc(vcpu), *vcpu_cpsr(vcpu));
		kvm_inject_undefined(vcpu);
	}

	return 1;
}

/* Initialize the guest's ID registers with KVM sanitised values. */
void kvm_arm_init_id_regs(struct kvm *kvm)
{
	int i;
	u32 id;
	u64 val;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++) {
		id = reg_to_encoding(&id_reg_descs[i]);
		if (WARN_ON_ONCE(!is_id_reg(id)))
			/* Shouldn't happen */
			continue;

		val = 0;
		/* Read KVM sanitised register value if available */
		if (id_reg_descs[i].reset)
			val = id_reg_descs[i].reset(NULL, &id_reg_descs[i]);

		IDREG(kvm, id) = val;
	}
}
