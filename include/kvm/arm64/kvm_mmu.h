/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef KVM_ARM64_KVM_MMU_H__
#define KVM_ARM64_KVM_MMU_H__

/*
 * We currently support using a VM-specified IPA size. For backward
 * compatibility, the default IPA size is fixed to 40bits.
 */
#define KVM_PHYS_SHIFT	(40)

/*
 * We are not in the kvm->srcu critical section most of the time, so we take
 * the SRCU read lock here. Since we copy the data from the user page, we
 * can immediately drop the lock again.
 */
static inline int kvm_read_guest_lock(struct kvm *kvm,
				      gpa_t gpa, void *data, unsigned long len)
{
	int srcu_idx = srcu_read_lock(&kvm->srcu);
	int ret = kvm_read_guest(kvm, gpa, data, len);

	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return ret;
}

static inline int kvm_write_guest_lock(struct kvm *kvm, gpa_t gpa,
				       const void *data, unsigned long len)
{
	int srcu_idx = srcu_read_lock(&kvm->srcu);
	int ret = kvm_write_guest(kvm, gpa, data, len);

	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return ret;
}

/* Implemented by each architecture */
int kvm_phys_addr_ioremap(struct kvm *kvm, phys_addr_t guest_ipa,
			  phys_addr_t pa, unsigned long size, bool writable);

int create_hyp_io_mappings(phys_addr_t phys_addr, size_t size,
			   void __iomem **kaddr,
			   void __iomem **haddr);

#endif /* KVM_ARM64_KVM_MMU_H__ */
