// SPDX-License-Identifier: GPL-2.0-only
/*
 * set_id_regs - Test for setting ID register from usersapce.
 *
 * Copyright (c) 2023 Google LLC.
 *
 *
 * Test that KVM supports setting ID registers from userspace and handles the
 * feature set correctly.
 */

#include <stdint.h>
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include <linux/bitfield.h>

#define field_get(_mask, _reg) (((_reg) & (_mask)) >> (ffsl(_mask) - 1))
#define field_prep(_mask, _val) (((_val) << (ffsl(_mask) - 1)) & (_mask))

struct reg_feature {
	uint64_t reg;
	uint64_t ftr_mask;
};

static void guest_code(void)
{
	for (;;)
		GUEST_SYNC(0);
}

static struct reg_feature lower_safe_reg_ftrs[] = {
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), ARM64_FEATURE_MASK(ID_AA64DFR0_WRPS) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64PFR0_EL1), ARM64_FEATURE_MASK(ID_AA64PFR0_EL3) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64MMFR0_EL1), ARM64_FEATURE_MASK(ID_AA64MMFR0_FGT) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64MMFR1_EL1), ARM64_FEATURE_MASK(ID_AA64MMFR1_PAN) },
	{ KVM_ARM64_SYS_REG(SYS_ID_AA64MMFR2_EL1), ARM64_FEATURE_MASK(ID_AA64MMFR2_FWB) },
};

static void test_user_set_lower_safe(struct kvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lower_safe_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = lower_safe_reg_ftrs + i;
		uint64_t val, new_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);

		/* Set a safe value for the feature */
		if (ftr > 0)
			ftr--;

		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);

		vcpu_set_reg(vcpu, reg_ftr->reg, val);
		vcpu_get_reg(vcpu, reg_ftr->reg, &new_val);
		ASSERT_EQ(new_val, val);
	}
}

static void test_user_set_fail(struct kvm_vcpu *vcpu)
{
	int i, r;

	for (i = 0; i < ARRAY_SIZE(lower_safe_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = lower_safe_reg_ftrs + i;
		uint64_t val, old_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);

		/* Set a invalid value (too big) for the feature */
		if (ftr >= GENMASK_ULL(ARM64_FEATURE_FIELD_BITS - 1, 0))
			continue;
		ftr++;

		old_val = val;
		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);

		r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
		TEST_ASSERT(r < 0 && errno == EINVAL,
			    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);
	}
}

static struct reg_feature exact_reg_ftrs[] = {
	/* Items will be added when there is appropriate field of type
	 * FTR_EXACT enabled writing from userspace later.
	 */
};

static void test_user_set_exact(struct kvm_vcpu *vcpu)
{
	int i, r;

	for (i = 0; i < ARRAY_SIZE(exact_reg_ftrs); i++) {
		struct reg_feature *reg_ftr = exact_reg_ftrs + i;
		uint64_t val, old_val, ftr;

		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ftr = field_get(reg_ftr->ftr_mask, val);
		old_val = val;

		/* Exact match */
		vcpu_set_reg(vcpu, reg_ftr->reg, val);
		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);

		/* Smaller value */
		if (ftr > 0) {
			ftr--;
			val &= ~reg_ftr->ftr_mask;
			val |= field_prep(reg_ftr->ftr_mask, ftr);
			r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
			TEST_ASSERT(r < 0 && errno == EINVAL,
				    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);
			vcpu_get_reg(vcpu, reg_ftr->reg, &val);
			ASSERT_EQ(val, old_val);
			ftr++;
		}

		/* Bigger value */
		ftr++;
		val &= ~reg_ftr->ftr_mask;
		val |= field_prep(reg_ftr->ftr_mask, ftr);
		r = __vcpu_set_reg(vcpu, reg_ftr->reg, val);
		TEST_ASSERT(r < 0 && errno == EINVAL,
			    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);
		vcpu_get_reg(vcpu, reg_ftr->reg, &val);
		ASSERT_EQ(val, old_val);
	}
}

static uint32_t writable_regs[] = {
	SYS_ID_DFR0_EL1,
	SYS_ID_AA64DFR0_EL1,
	SYS_ID_AA64PFR0_EL1,
	SYS_ID_AA64MMFR0_EL1,
	SYS_ID_AA64MMFR1_EL1,
	SYS_ID_AA64MMFR2_EL1,
};

void test_user_get_writable_masks(struct kvm_vm *vm)
{
	struct feature_id_writable_masks masks;

	vm_ioctl(vm, KVM_ARM_GET_FEATURE_ID_WRITABLE_MASKS, &masks);

	for (int i = 0; i < ARRAY_SIZE(writable_regs); i++) {
		uint32_t reg = writable_regs[i];
		int idx = ARM64_FEATURE_ID_SPACE_IDX(sys_reg_Op0(reg),
				sys_reg_Op1(reg), sys_reg_CRn(reg),
				sys_reg_CRm(reg), sys_reg_Op2(reg));

		ASSERT_EQ(masks.mask[idx], GENMASK_ULL(63, 0));
	}
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	ksft_print_header();
	ksft_set_plan(4);

	test_user_get_writable_masks(vm);
	ksft_test_result_pass("test_user_get_writable_masks\n");

	test_user_set_exact(vcpu);
	ksft_test_result_pass("test_user_set_exact\n");

	test_user_set_fail(vcpu);
	ksft_test_result_pass("test_user_set_fail\n");

	test_user_set_lower_safe(vcpu);
	ksft_test_result_pass("test_user_set_lower_safe\n");

	kvm_vm_free(vm);

	ksft_finished();
}
