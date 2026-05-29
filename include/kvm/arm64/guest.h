/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_ARM64_GUEST_H__
#define __KVM_ARM64_GUEST_H__

/* Implemented by virt/kvm/arm64/guest.c */
unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);

#endif /* __KVM_ARM64_GUEST_H__ */
