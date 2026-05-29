// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_emulate.h>

#include <kvm/arm64/handle_exit.h>

#define PSCI_0_2_FN_SYSTEM_OFF		0x84000008
#define PSCI_RET_NOT_SUPPORTED		-1
#define PSCI_RET_INTERNAL_FAILURE	-6
/*
 * Temporary smc/hvc handler. Non-compliant implementation (features missing).
 * Implements only system off so that test programs are able to end their execution
 */
static int kvm_smccc_call_handler(struct kvm_vcpu *vcpu)
{
	u32 func_id = vcpu_get_reg(vcpu, 0);
	u64 val = PSCI_RET_NOT_SUPPORTED;
	int ret = 1;

	if (func_id == PSCI_0_2_FN_SYSTEM_OFF) {
		spin_lock(&vcpu->arch.mp_state_lock);
		WRITE_ONCE(vcpu->arch.mp_state.mp_state, KVM_MP_STATE_STOPPED);
		spin_unlock(&vcpu->arch.mp_state_lock);
		kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_SLEEP);
		memset(&vcpu->run->system_event, 0,
		       sizeof(vcpu->run->system_event));
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SHUTDOWN;
		vcpu->run->system_event.ndata = 1;
		vcpu->run->system_event.data[0] = 0;
		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		val = PSCI_RET_INTERNAL_FAILURE;
		ret = 0;
	}
	vcpu_set_reg(vcpu, 0, val);

	return ret;
}

static int handle_hvc(struct kvm_vcpu *vcpu)
{
	vcpu->stat.hvc_exit_stat++;
	return kvm_smccc_call_handler(vcpu);
}

exit_handle_fn arm_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]	= kvm_handle_unknown_ec,
	[ESR_ELx_EC_HVC64]	= handle_hvc,
};
