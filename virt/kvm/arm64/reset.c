// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm_host.h>
#include <asm/pstate.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>
#include <kvm/arm64/reset.h>

/*
 * ARMv8 Reset Values
 */
#define VCPU_RESET_PSTATE_EL1	(PSR_MODE_EL1h | PSR_A_BIT | PSR_I_BIT | \
				 PSR_F_BIT | PSR_D_BIT)

#define VCPU_RESET_PSTATE_EL2	(PSR_MODE_EL2h | PSR_A_BIT | PSR_I_BIT | \
				 PSR_F_BIT | PSR_D_BIT)

#define VCPU_RESET_PSTATE_SVC	(PSR_AA32_MODE_SVC | PSR_AA32_A_BIT | \
				 PSR_AA32_I_BIT | PSR_AA32_F_BIT)

void kvm_reset_vcpu_core_regs(struct kvm_vcpu *vcpu)
{
	u64 pstate;

	if (vcpu_el1_is_32bit(vcpu))
		pstate = VCPU_RESET_PSTATE_SVC;
	else if (vcpu_has_nv(vcpu))
		pstate = VCPU_RESET_PSTATE_EL2;
	else
		pstate = VCPU_RESET_PSTATE_EL1;

	/* Reset core registers */
	memset(vcpu_gp_regs(vcpu), 0, sizeof(vcpu_gp_regs(vcpu)));
	*vcpu_pc(vcpu) = 0;
	memset(kvm_vcpu_get_vregs(vcpu), 0, sizeof(*kvm_vcpu_get_vregs(vcpu)));
	memset(kvm_vcpu_get_fpsr(vcpu), 0, sizeof(*kvm_vcpu_get_fpsr(vcpu)));
	memset(kvm_vcpu_get_fpcr(vcpu), 0, sizeof(*kvm_vcpu_get_fpcr(vcpu)));
	vcpu->arch.ctxt.spsr_abt = 0;
	vcpu->arch.ctxt.spsr_und = 0;
	vcpu->arch.ctxt.spsr_irq = 0;
	vcpu->arch.ctxt.spsr_fiq = 0;
	*vcpu_cpsr(vcpu) = pstate;
}
