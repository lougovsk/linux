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

/*
 * Number of entries in id_reg_desc's ftr_bits[] (Number of 4 bits fields
 * in 64 bit register + 1 entry for a terminator entry).
 */
#define	FTR_FIELDS_NUM	17

struct id_reg_desc {
	const struct sys_reg_desc	reg_desc;
	/*
	 * KVM sanitised ID register value.
	 * It is the default value for per VM emulated ID register.
	 */
	u64 kvm_sys_val;
	/*
	 * Used to validate the ID register values with arm64_check_features().
	 * The last item in the array must be terminated by an item whose
	 * width field is zero as that is expected by arm64_check_features().
	 * Only feature bits defined in this array are writable.
	 */
	struct arm64_ftr_bits	ftr_bits[FTR_FIELDS_NUM];

	/*
	 * Basically init() is used to setup the KVM sanitised value
	 * stored in kvm_sys_val.
	 */
	void (*init)(struct id_reg_desc *idr);
};

static struct id_reg_desc id_reg_descs[];

/**
 * arm64_check_features() - Check if a feature register value constitutes
 * a subset of features indicated by @limit.
 *
 * @ftrp: Pointer to an array of arm64_ftr_bits. It must be terminated by
 * an item whose width field is zero.
 * @val: The feature register value to check
 * @limit: The limit value of the feature register
 *
 * This function will check if each feature field of @val is the "safe" value
 * against @limit based on @ftrp[], each of which specifies the target field
 * (shift, width), whether or not the field is for a signed value (sign),
 * how the field is determined to be "safe" (type), and the safe value
 * (safe_val) when type == FTR_EXACT (safe_val won't be used by this
 * function when type != FTR_EXACT). Any other fields in arm64_ftr_bits
 * won't be used by this function. If a field value in @val is the same
 * as the one in @limit, it is always considered the safe value regardless
 * of the type. For register fields that are not in @ftrp[], only the value
 * in @limit is considered the safe value.
 *
 * Return: 0 if all the fields are safe. Otherwise, return negative errno.
 */
static int arm64_check_features(const struct arm64_ftr_bits *ftrp, u64 val, u64 limit)
{
	u64 mask = 0;

	for (; ftrp->width; ftrp++) {
		s64 f_val, f_lim, safe_val;

		f_val = arm64_ftr_value(ftrp, val);
		f_lim = arm64_ftr_value(ftrp, limit);
		mask |= arm64_ftr_mask(ftrp);

		if (f_val == f_lim)
			safe_val = f_val;
		else
			safe_val = arm64_ftr_safe_value(ftrp, f_val, f_lim);

		if (safe_val != f_val)
			return -E2BIG;
	}

	/*
	 * For fields that are not indicated in ftrp, values in limit are the
	 * safe values.
	 */
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
	else
		return 0;
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

/*
 * Return true if the register's (Op0, Op1, CRn, CRm, Op2) is
 * (3, 0, 0, crm, op2), where 1<=crm<8, 0<=op2<8.
 */
static bool is_id_reg(u32 id)
{
	return (sys_reg_Op0(id) == 3 && sys_reg_Op1(id) == 0 &&
		sys_reg_CRn(id) == 0 && sys_reg_CRm(id) >= 1 &&
		sys_reg_CRm(id) < 8);
}

u64 kvm_arm_read_id_reg_with_encoding(const struct kvm_vcpu *vcpu, u32 id)
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
	int ret;
	int id = reg_to_encoding(rd);

	ret = arm64_check_features(id_reg_descs[IDREG_IDX(id)].ftr_bits, val,
				   id_reg_descs[IDREG_IDX(id)].kvm_sys_val);
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

static void init_id_reg(struct id_reg_desc *idr)
{
	idr->kvm_sys_val = read_sanitised_ftr_reg(reg_to_encoding(&idr->reg_desc));
}

static void init_id_aa64pfr0_el1(struct id_reg_desc *idr)
{
	u64 val;
	u32 id = reg_to_encoding(&idr->reg_desc);

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

	val &= ~ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_GIC);
	val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_GIC), 1);

	idr->kvm_sys_val = val;
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
	if (csv2 > 1 ||
	    (csv2 && arm64_get_spectre_v2_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	/* Same thing for CSV3 */
	csv3 = cpuid_feature_extract_unsigned_field(val, ID_AA64PFR0_EL1_CSV3_SHIFT);
	if (csv3 > 1 ||
	    (csv3 && arm64_get_meltdown_state() != SPECTRE_UNAFFECTED))
		return -EINVAL;

	return set_id_reg(vcpu, rd, val);
}

static void init_id_aa64dfr0_el1(struct id_reg_desc *idr)
{
	u64 val;
	u32 id = reg_to_encoding(&idr->reg_desc);

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

	idr->kvm_sys_val = val;
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

	if (valid_pmu) {
		return set_id_reg(vcpu, rd, val);
	} else {
		/* We can only differ with PMUver, and anything else is an error */
		val ^= read_id_reg(vcpu, rd);
		val &= ~ARM64_FEATURE_MASK(ID_AA64DFR0_EL1_PMUVer);
		if (val)
			return -EINVAL;

		if (pmuver == ID_AA64DFR0_EL1_PMUVer_IMP_DEF)
			set_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags);
		else
			clear_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags);

		return 0;
	}
}

static void init_id_dfr0_el1(struct id_reg_desc *idr)
{
	u64 val;
	u32 id = reg_to_encoding(&idr->reg_desc);

	val = read_sanitised_ftr_reg(id);
	/*
	 * Initialise the default PMUver before there is a chance to
	 * create an actual PMU.
	 */
	val &= ~ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon);
	val |= FIELD_PREP(ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon),
			  kvm_arm_pmu_get_pmuver_limit());

	idr->kvm_sys_val = val;
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

	if (valid_pmu) {
		return set_id_reg(vcpu, rd, val);
	} else {
		/* We can only differ with PerfMon, and anything else is an error */
		val ^= read_id_reg(vcpu, rd);
		val &= ~ARM64_FEATURE_MASK(ID_DFR0_EL1_PerfMon);
		if (val)
			return -EINVAL;

		if (perfmon == ID_DFR0_EL1_PerfMon_IMPDEF)
			set_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags);
		else
			clear_bit(KVM_ARCH_FLAG_VCPU_HAS_IMP_DEF_PMU, &vcpu->kvm->arch.flags);

		return 0;
	}
}

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define SYS_DESC_SANITISED(name) {			\
	SYS_DESC(SYS_##name),				\
	.access	= access_id_reg,			\
	.get_user = get_id_reg,				\
	.set_user = set_id_reg,				\
	.visibility = id_visibility,			\
}

#define ID_SANITISED(name) {				\
	.reg_desc = SYS_DESC_SANITISED(name),		\
	.ftr_bits = { ARM64_FTR_END, },			\
	.init = init_id_reg,				\
}

/* sys_reg_desc initialiser for known cpufeature ID registers */
#define AA32_ID_SANITISED(name) {			\
	.reg_desc = {					\
		SYS_DESC(SYS_##name),			\
		.access	= access_id_reg,		\
		.get_user = get_id_reg,			\
		.set_user = set_id_reg,			\
		.visibility = aa32_id_visibility,	\
	},						\
	.ftr_bits = { ARM64_FTR_END, },			\
	.init = init_id_reg,				\
}

/*
 * sys_reg_desc initialiser for architecturally unallocated cpufeature ID
 * register with encoding Op0=3, Op1=0, CRn=0, CRm=crm, Op2=op2
 * (1 <= crm < 8, 0 <= Op2 < 8).
 */
#define ID_UNALLOCATED(crm, op2) {				\
	.reg_desc = {						\
		Op0(3), Op1(0), CRn(0), CRm(crm), Op2(op2),	\
		.access = access_id_reg,			\
		.get_user = get_id_reg,				\
		.set_user = set_id_reg,				\
		.visibility = raz_visibility			\
	},							\
	.ftr_bits = { ARM64_FTR_END, },				\
}

/*
 * sys_reg_desc initialiser for known ID registers that we hide from guests.
 * For now, these are exposed just like unallocated ID regs: they appear
 * RAZ for the guest.
 */
#define ID_HIDDEN(name) {				\
	.reg_desc = {					\
		SYS_DESC(SYS_##name),			\
		.access = access_id_reg,		\
		.get_user = get_id_reg,			\
		.set_user = set_id_reg,			\
		.visibility = raz_visibility,		\
	},						\
	.ftr_bits = { ARM64_FTR_END, },			\
}

static struct id_reg_desc id_reg_descs[KVM_ARM_ID_REG_NUM] = {
	/*
	 * ID regs: all ID_SANITISED() entries here must have corresponding
	 * entries in arm64_ftr_regs[].
	 */

	/* AArch64 mappings of the AArch32 ID registers */
	/* CRm=1 */
	AA32_ID_SANITISED(ID_PFR0_EL1),
	AA32_ID_SANITISED(ID_PFR1_EL1),
	{ .reg_desc = {
		SYS_DESC(SYS_ID_DFR0_EL1),
		.access = access_id_reg,
		.get_user = get_id_reg,
		.set_user = set_id_dfr0_el1,
		.visibility = aa32_id_visibility, },
	  .ftr_bits = {
		ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE,
			ID_DFR0_EL1_PerfMon_SHIFT, ID_DFR0_EL1_PerfMon_WIDTH, 0),
		ARM64_FTR_END, },
	  .init = init_id_dfr0_el1,
	},
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
	{ .reg_desc = {
		SYS_DESC(SYS_ID_AA64PFR0_EL1),
		.access = access_id_reg,
		.get_user = get_id_reg,
		.set_user = set_id_aa64pfr0_el1, },
	  .ftr_bits = {
		ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE,
			ID_AA64PFR0_EL1_CSV2_SHIFT, ID_AA64PFR0_EL1_CSV2_WIDTH, 0),
		ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE,
			ID_AA64PFR0_EL1_CSV3_SHIFT, ID_AA64PFR0_EL1_CSV3_WIDTH, 0),
		ARM64_FTR_END, },
	  .init = init_id_aa64pfr0_el1,
	},
	ID_SANITISED(ID_AA64PFR1_EL1),
	ID_UNALLOCATED(4, 2),
	ID_UNALLOCATED(4, 3),
	ID_SANITISED(ID_AA64ZFR0_EL1),
	ID_HIDDEN(ID_AA64SMFR0_EL1),
	ID_UNALLOCATED(4, 6),
	ID_UNALLOCATED(4, 7),

	/* CRm=5 */
	{ .reg_desc = {
		SYS_DESC(SYS_ID_AA64DFR0_EL1),
		.access = access_id_reg,
		.get_user = get_id_reg,
		.set_user = set_id_aa64dfr0_el1, },
	  .ftr_bits = {
		ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE,
			ID_AA64DFR0_EL1_PMUVer_SHIFT, ID_AA64DFR0_EL1_PMUVer_WIDTH, 0),
		ARM64_FTR_END, },
	  .init = init_id_aa64dfr0_el1,
	},
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

const struct sys_reg_desc *kvm_arm_find_id_reg(const struct sys_reg_params *params)
{
	u32 id;

	id = reg_to_encoding(params);
	if (!is_id_reg(id))
		return NULL;

	return &id_reg_descs[IDREG_IDX(id)].reg_desc;
}

void kvm_arm_reset_id_regs(struct kvm_vcpu *vcpu)
{
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++)
		if (id_reg_descs[i].reg_desc.reset)
			id_reg_descs[i].reg_desc.reset(vcpu, &id_reg_descs[i].reg_desc);
}

int kvm_arm_get_id_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	u64 __user *uaddr = (u64 __user *)(unsigned long)reg->addr;
	const struct sys_reg_desc *r;
	struct sys_reg_params params;
	u64 val;
	int ret;
	u32 id;

	if (!index_to_params(reg->id, &params))
		return -ENOENT;
	id = reg_to_encoding(&params);

	if (!is_id_reg(id))
		return -ENOENT;

	r = &id_reg_descs[IDREG_IDX(id)].reg_desc;
	if (r->get_user) {
		ret = (r->get_user)(vcpu, r, &val);
	} else {
		ret = 0;
		val = 0;
	}

	if (!ret)
		ret = put_user(val, uaddr);

	return ret;
}

int kvm_arm_set_id_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	u64 __user *uaddr = (u64 __user *)(unsigned long)reg->addr;
	const struct sys_reg_desc *r;
	struct sys_reg_params params;
	u64 val;
	int ret;
	u32 id;

	if (!index_to_params(reg->id, &params))
		return -ENOENT;
	id = reg_to_encoding(&params);

	if (!is_id_reg(id))
		return -ENOENT;

	if (get_user(val, uaddr))
		return -EFAULT;

	r = &id_reg_descs[IDREG_IDX(id)].reg_desc;

	if (sysreg_user_write_ignore(vcpu, r))
		return 0;

	if (r->set_user)
		ret = (r->set_user)(vcpu, r, val);
	else
		ret = 0;

	return ret;
}

bool kvm_arm_idreg_table_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++) {
		const struct sys_reg_desc *r = &id_reg_descs[i].reg_desc;

		if (r->reg && !r->reset) {
			kvm_err("sys_reg table %pS entry %d lacks reset\n", r, i);
			return false;
		}

		if (i && cmp_sys_reg(&id_reg_descs[i-1].reg_desc, r) >= 0) {
			kvm_err("sys_reg table %pS entry %d out of order\n",
				&id_reg_descs[i - 1].reg_desc, i - 1);
			return false;
		}

		if (id_reg_descs[i].init)
			id_reg_descs[i].init(&id_reg_descs[i]);
	}

	return true;
}

/* Assumed ordered tables, see kvm_sys_reg_table_init. */
int kvm_arm_walk_id_regs(struct kvm_vcpu *vcpu, u64 __user *uind)
{
	const struct id_reg_desc *i2, *end2;
	unsigned int total = 0;
	int err;

	i2 = id_reg_descs;
	end2 = id_reg_descs + ARRAY_SIZE(id_reg_descs);

	for (; i2 != end2; i2++) {
		err = walk_one_sys_reg(vcpu, &(i2->reg_desc), &uind, &total);
		if (err)
			return err;
	}
	return total;
}

/*
 * Initialize the guest's ID registers with KVM sanitised values that were setup
 * during ID register descriptors initialization.
 */
void kvm_arm_init_id_regs(struct kvm *kvm)
{
	int i;
	u32 id;

	for (i = 0; i < ARRAY_SIZE(id_reg_descs); i++) {
		id = reg_to_encoding(&id_reg_descs[i].reg_desc);
		IDREG(kvm, id) = id_reg_descs[i].kvm_sys_val;
	}
}
