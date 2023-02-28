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

static u8 vcpu_pmuver(const struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_has_pmu(vcpu))
		return vcpu->kvm->arch.dfr0_pmuver.imp;

	return vcpu->kvm->arch.dfr0_pmuver.unimp;
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

u64 kvm_arm_read_id_reg_with_encoding(const struct kvm_vcpu *vcpu, u32 id)
{
	u64 val = IDREG(vcpu->kvm, id);

	switch (id) {
	case SYS_ID_AA64PFR0_EL1:
		if (!vcpu_has_sve(vcpu))
			val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_SVE);
		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_AMU);
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
		/* Limit debug to ARMv8.0 */
		val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_DebugVer);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_DebugVer), 6);
		/* Set PMUver to the required version */
		val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer),
				  vcpu_pmuver(vcpu));
		/* Hide SPE from guests */
		val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMSVer);
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

	return kvm_arm_read_id_reg_with_encoding(vcpu, reg_to_encoding(r));
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
	/* This is what we mean by invariant: you can't change it. */
	if (val != read_id_reg(vcpu, rd))
		return -EINVAL;

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

static int set_id_aa64pfr0_el1(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 val)
{
	u8 csv2, csv3;
	u64 sval = val;

	/*
	 * Allow AA64PFR0_EL1.CSV2 to be set from userspace as long as
	 * it doesn't promise more than what is actually provided (the
	 * guest could otherwise be covered in ectoplasmic residue).
	 */
	csv2 = cpuid_feature_extract_unsigned_field(val, ID_AA64PFR0_EL1_CSV2_SHIFT);
	if (csv2 > 1 ||
	    (csv2 && arm64_get_spectre_v2_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	/* Same thing for CSV3 */
	csv3 = cpuid_feature_extract_unsigned_field(val, ID_AA64PFR0_EL1_CSV3_SHIFT);
	if (csv3 > 1 ||
	    (csv3 && arm64_get_meltdown_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	/* We can only differ with CSV[23], and anything else is an error */
	val ^= read_id_reg(vcpu, rd);
	val &= ~(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV2) |
		 ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV3));
	if (val)
		return -EINVAL;

	IDREG_RD(vcpu->kvm, rd) = sval;

	return 0;
}

static int set_id_aa64dfr0_el1(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 val)
{
	u8 pmuver, host_pmuver;
	bool valid_pmu;

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

	/* We can only differ with PMUver, and anything else is an error */
	val ^= read_id_reg(vcpu, rd);
	val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer);
	if (val)
		return -EINVAL;

	if (valid_pmu)
		vcpu->kvm->arch.dfr0_pmuver.imp = pmuver;
	else
		vcpu->kvm->arch.dfr0_pmuver.unimp = pmuver;

	return 0;
}

static int set_id_dfr0_el1(struct kvm_vcpu *vcpu,
			   const struct sys_reg_desc *rd,
			   u64 val)
{
	u8 perfmon, host_perfmon;
	bool valid_pmu;

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

	/* We can only differ with PerfMon, and anything else is an error */
	val ^= read_id_reg(vcpu, rd);
	val &= ~ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon);
	if (val)
		return -EINVAL;

	if (valid_pmu)
		vcpu->kvm->arch.dfr0_pmuver.imp = perfmon_to_pmuver(perfmon);
	else
		vcpu->kvm->arch.dfr0_pmuver.unimp = perfmon_to_pmuver(perfmon);

	return 0;
}

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define ID_SANITISED(name) {			\
	SYS_DESC(SYS_##name),			\
	.access	= access_id_reg,		\
	.get_user = get_id_reg,			\
	.set_user = set_id_reg,			\
	.visibility = id_visibility,		\
}

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define AA32_ID_SANITISED(name) {		\
	SYS_DESC(SYS_##name),			\
	.access	= access_id_reg,		\
	.get_user = get_id_reg,			\
	.set_user = set_id_reg,			\
	.visibility = aa32_id_visibility,	\
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
	.visibility = raz_visibility			\
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
}

static const struct sys_reg_desc id_reg_descs[] = {
	/*
	 * ID regs: all ID_SANITISED() entries here must have corresponding
	 * entries in arm64_ftr_regs[].
	 */

	/* AArch64 mappings of the AArch32 ID registers */
	/* CRm=1 */
	AA32_ID_SANITISED(ID_PFR0_EL1),
	AA32_ID_SANITISED(ID_PFR1_EL1),
	{ SYS_DESC(SYS_ID_DFR0_EL1), .access = access_id_reg,
	  .get_user = get_id_reg, .set_user = set_id_dfr0_el1,
	  .visibility = aa32_id_visibility, },
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
	{ SYS_DESC(SYS_ID_AA64PFR0_EL1), .access = access_id_reg,
	  .get_user = get_id_reg, .set_user = set_id_aa64pfr0_el1, },
	ID_SANITISED(ID_AA64PFR1_EL1),
	ID_UNALLOCATED(4, 2),
	ID_UNALLOCATED(4, 3),
	ID_SANITISED(ID_AA64ZFR0_EL1),
	ID_HIDDEN(ID_AA64SMFR0_EL1),
	ID_UNALLOCATED(4, 6),
	ID_UNALLOCATED(4, 7),

	/* CRm=5 */
	{ SYS_DESC(SYS_ID_AA64DFR0_EL1), .access = access_id_reg,
	  .get_user = get_id_reg, .set_user = set_id_aa64dfr0_el1, },
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


void kvm_arm_reset_id_regs(struct kvm_vcpu *vcpu)
{
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++)
		if (id_reg_descs[i].reset)
			id_reg_descs[i].reset(vcpu, &id_reg_descs[i]);
}

int kvm_arm_get_id_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	return kvm_sys_reg_get_user(vcpu, reg,
				    id_reg_descs, ARRAY_SIZE(id_reg_descs));
}

int kvm_arm_set_id_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	return kvm_sys_reg_set_user(vcpu, reg,
				    id_reg_descs, ARRAY_SIZE(id_reg_descs));
}

bool kvm_arm_check_idreg_table(void)
{
	return check_sysreg_table(id_reg_descs, ARRAY_SIZE(id_reg_descs), false);
}

int kvm_arm_walk_id_regs(struct kvm_vcpu *vcpu, u64 __user *uind)
{
	const struct sys_reg_desc *i2, *end2;
	unsigned int total = 0;
	int err;

	i2 = id_reg_descs;
	end2 = id_reg_descs + ARRAY_SIZE(id_reg_descs);

	while (i2 != end2) {
		err = walk_one_sys_reg(vcpu, i2++, &uind, &total);
		if (err)
			return err;
	}
	return total;
}

/*
 * Set the guest's ID registers that are defined in id_reg_descs[]
 * with ID_SANITISED() to the host's sanitized value.
 */
void kvm_arm_set_default_id_regs(struct kvm *kvm)
{
	int i;
	u32 id;
	u64 val;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++) {
		id = reg_to_encoding(&id_reg_descs[i]);
		if (WARN_ON_ONCE(!is_id_reg(id)))
			/* Shouldn't happen */
			continue;

		if (id_reg_descs[i].visibility == raz_visibility)
			/* Hidden or reserved ID register */
			continue;

		val = read_sanitised_ftr_reg(id);
		IDREG(kvm, id) = val;
	}
	/*
	 * The default is to expose CSV2 == 1 if the HW isn't affected.
	 * Although this is a per-CPU feature, we make it global because
	 * asymmetric systems are just a nuisance.
	 *
	 * Userspace can override this as long as it doesn't promise
	 * the impossible.
	 */
	val = IDREG(kvm, SYS_ID_AA64PFR0_EL1);

	if (arm64_get_spectre_v2_state() == SPECTRE_UNAFFECTED) {
		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV2);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV2), 1);
	}
	if (arm64_get_meltdown_state() == SPECTRE_UNAFFECTED) {
		val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV3);
		val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_CSV3), 1);
	}

	IDREG(kvm, SYS_ID_AA64PFR0_EL1) = val;
}
