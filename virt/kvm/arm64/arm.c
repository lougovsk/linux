// SPDX-License-Identifier: GPL-2.0-only

#include <linux/preempt.h>
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

int kvm_vcpu_init_check_features(struct kvm_vcpu *vcpu,
				 const struct kvm_vcpu_init *init)
{
	unsigned long features = init->features[0];
	int i;

	if (features & ~KVM_VCPU_VALID_FEATURES)
		return -ENOENT;

	for (i = 1; i < ARRAY_SIZE(init->features); i++) {
		if (init->features[i])
			return -ENOENT;
	}

	if (features & ~system_supported_vcpu_features())
		return -EINVAL;

	/*
	 * For now make sure that both address/generic pointer authentication
	 * features are requested by the userspace together.
	 */
	if (test_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, &features) !=
	    test_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, &features))
		return -EINVAL;

	if (!test_bit(KVM_ARM_VCPU_EL1_32BIT, &features))
		return 0;

	/* MTE is incompatible with AArch32 */
	if (kvm_has_mte(vcpu->kvm))
		return -EINVAL;

	/* NV is incompatible with AArch32 */
	if (test_bit(KVM_ARM_VCPU_HAS_EL2, &features))
		return -EINVAL;

	return 0;
}

bool kvm_vcpu_init_changed(struct kvm_vcpu *vcpu,
			   const struct kvm_vcpu_init *init)
{
	unsigned long features = init->features[0];

	return !bitmap_equal(vcpu->kvm->arch.vcpu_features, &features,
			     KVM_VCPU_MAX_FEATURES);
}

int kvm_vm_type_ipa_size_shift(unsigned long type)
{
	int phys_shift;

	phys_shift = KVM_VM_TYPE_ARM_IPA_SIZE(type);
	if (phys_shift) {
		if (phys_shift > get_kvm_ipa_limit() ||
		    phys_shift < ARM64_MIN_PARANGE_BITS)
			return -EINVAL;
	} else {
		phys_shift = KVM_PHYS_SHIFT;
		if (phys_shift > get_kvm_ipa_limit()) {
			pr_warn_once("%s using unsupported default IPA limit, upgrade your VMM\n",
				     current->comm);
			return -EINVAL;
		}
	}

	return phys_shift;
}
