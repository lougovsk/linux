/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Ampere Computing
 */
#ifndef SELFTEST_NV_UTIL_H
#define SELFTEST_NV_UTIL_H

#include <linux/bitmap.h>

/* NV helpers */
static inline void init_vcpu_nested(struct kvm_vcpu_init *init)
{
	init->features[0] |= (1 << KVM_ARM_VCPU_HAS_EL2);
}

static inline bool kvm_arm_vcpu_has_el2(struct kvm_vcpu_init *init)
{
	unsigned long features = init->features[0];

	return test_bit(KVM_ARM_VCPU_HAS_EL2, &features);
}

static inline bool is_vcpu_nested(struct kvm_vcpu *vcpu)
{
	return vcpu->nested;
}

#endif /* SELFTEST_NV_UTIL_H */
