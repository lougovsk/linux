/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KVM_ARM64_HANDLE_EXIT_H
#define KVM_ARM64_HANDLE_EXIT_H

#include <linux/kvm_host.h>

typedef int (*exit_handle_fn)(struct kvm_vcpu *);
extern exit_handle_fn arm_exit_handlers[255];

int kvm_handle_unknown_ec(struct kvm_vcpu *vcpu);
exit_handle_fn kvm_get_exit_handler(struct kvm_vcpu *vcpu);
int handle_trap_exceptions(struct kvm_vcpu *vcpu);

#endif /* KVM_ARM64_HANDLE_EXIT_H */
