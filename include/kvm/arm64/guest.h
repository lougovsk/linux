/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_ARM64_GUEST_H__
#define __KVM_ARM64_GUEST_H__

/* Implemented by virt/kvm/arm64/guest.c */
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);
int get_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int set_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int copy_core_reg_indices(const struct kvm_vcpu *vcpu, u64 __user *uindices);
unsigned long num_core_regs(const struct kvm_vcpu *vcpu);

#endif /* __KVM_ARM64_GUEST_H__ */
