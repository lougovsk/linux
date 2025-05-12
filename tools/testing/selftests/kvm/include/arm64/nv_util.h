/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Ampere Computing
 */
#ifndef SELFTEST_NV_UTIL_H
#define SELFTEST_NV_UTIL_H

#include <linux/bitmap.h>
#include <vgic.h>

#define HCR_NV2		(UL(1) << 45)
#define HCR_AT		(UL(1) << 44)
#define HCR_NV		(UL(1) << 42)
#define HCR_E2H		(UL(1) << 34)
#define HCR_TTLB        (UL(1) << 25)

/* Enable NV2 and guest in VHE mode */
#define HCR_EL2_NV_EANBLE (HCR_E2H | HCR_NV | HCR_NV2 | HCR_AT | HCR_TTLB)

struct kvm_vm *nv_vm_create_with_vcpus_gic(uint32_t nr_vcpus,
		struct kvm_vcpu **vcpus, int *gic_fd, void *guest_code);

struct kvm_vm *__nv_vm_create_with_vcpus_gic(struct vm_shape shape,
		uint32_t nr_vcpus, struct kvm_vcpu **vcpus,
		uint64_t extra_mem_pages, int *gic_fd, void *guest_code);

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
