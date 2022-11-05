// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/tracepoint.h>

#include <asm/kvm_emulate.h>

#include "trace_arm.h"

static void kvm_entry_tp(void *data, struct kvm_vcpu *vcpu)
{
	if (trace_kvm_entry_enabled())
		trace_kvm_entry(*vcpu_pc(vcpu));

	if (trace_kvm_entry_v2_enabled())
		trace_kvm_entry_v2(vcpu);
}

static void kvm_exit_tp(void *data, int ret, struct kvm_vcpu *vcpu)
{
	if (trace_kvm_exit_enabled())
		trace_kvm_exit(ret, kvm_vcpu_trap_get_class(vcpu),
			       *vcpu_pc(vcpu));

	if (trace_kvm_exit_v2_enabled())
		trace_kvm_exit_v2(ret, vcpu);
}

static int __init kvm_tp_init(void)
{
	register_trace_kvm_entry_tp(kvm_entry_tp, NULL);
	register_trace_kvm_exit_tp(kvm_exit_tp, NULL);
	return 0;
}

core_initcall(kvm_tp_init)
