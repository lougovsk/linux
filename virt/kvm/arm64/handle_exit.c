// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_emulate.h>

#include <kvm/arm64/handle_exit.h>

int kvm_handle_unknown_ec(struct kvm_vcpu *vcpu)
{
	u64 esr = kvm_vcpu_get_esr(vcpu);

	kvm_pr_unimpl("Unknown exception class: esr: %#016llx -- %s\n",
		      esr, esr_get_class_string(esr));

	kvm_inject_undefined(vcpu);
	return 1;
}

exit_handle_fn kvm_get_exit_handler(struct kvm_vcpu *vcpu)
{
	u64 esr = kvm_vcpu_get_esr(vcpu);
	u8 esr_ec = ESR_ELx_EC(esr);

	return arm_exit_handlers[esr_ec];
}

/*
 * We may be single-stepping an emulated instruction. If the emulation
 * has been completed in the kernel, we can return to userspace with a
 * KVM_EXIT_DEBUG, otherwise userspace needs to complete its
 * emulation first.
 */
int handle_trap_exceptions(struct kvm_vcpu *vcpu)
{
	int handled;

	/*
	 * See ARM ARM B1.14.1: "Hyp traps on instructions
	 * that fail their condition code check"
	 */
	if (!kvm_condition_valid(vcpu)) {
		kvm_incr_pc(vcpu);
		handled = 1;
	} else {
		exit_handle_fn exit_handler;

		exit_handler = kvm_get_exit_handler(vcpu);
		handled = exit_handler(vcpu);
	}

	return handled;
}
