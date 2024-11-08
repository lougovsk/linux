// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debug and Guest Debug support
 *
 * Copyright (C) 2015 - Linaro Ltd
 * Author: Alex Bennée <alex.bennee@linaro.org>
 */

#include <linux/kvm_host.h>
#include <linux/hw_breakpoint.h>

#include <asm/debug-monitors.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>

#include "trace.h"

/**
 * kvm_arm_setup_mdcr_el2 - configure vcpu mdcr_el2 value
 *
 * @vcpu:	the vcpu pointer
 *
 * This ensures we will trap access to:
 *  - Performance monitors (MDCR_EL2_TPM/MDCR_EL2_TPMCR)
 *  - Debug ROM Address (MDCR_EL2_TDRA)
 *  - OS related registers (MDCR_EL2_TDOSA)
 *  - Statistical profiler (MDCR_EL2_TPMS/MDCR_EL2_E2PB)
 *  - Self-hosted Trace Filter controls (MDCR_EL2_TTRF)
 *  - Self-hosted Trace (MDCR_EL2_TTRF/MDCR_EL2_E2TB)
 */
static void kvm_arm_setup_mdcr_el2(struct kvm_vcpu *vcpu)
{
	/*
	 * This also clears MDCR_EL2_E2PB_MASK and MDCR_EL2_E2TB_MASK
	 * to disable guest access to the profiling and trace buffers
	 */
	vcpu->arch.mdcr_el2 = FIELD_PREP(ARMV8_PMU_PMCR_N,
					 *host_data_ptr(nr_event_counters));
	vcpu->arch.mdcr_el2 |= (MDCR_EL2_TPM |
				MDCR_EL2_TPMS |
				MDCR_EL2_TTRF |
				MDCR_EL2_TPMCR |
				MDCR_EL2_TDRA |
				MDCR_EL2_TDOSA);

	/* Is the VM being debugged by userspace? */
	if (vcpu->guest_debug)
		/* Route all software debug exceptions to EL2 */
		vcpu->arch.mdcr_el2 |= MDCR_EL2_TDE;

	/*
	 * Trap debug registers if the guest doesn't have ownership of them.
	 */
	if (!kvm_guest_owns_debug_regs(vcpu))
		vcpu->arch.mdcr_el2 |= MDCR_EL2_TDA;
}

void kvm_init_host_debug_data(void)
{
	u64 dfr0 = read_sysreg(id_aa64dfr0_el1);

	if (cpuid_feature_extract_signed_field(dfr0, ID_AA64DFR0_EL1_PMUVer_SHIFT) > 0)
		*host_data_ptr(nr_event_counters) = FIELD_GET(ARMV8_PMU_PMCR_N,
							      read_sysreg(pmcr_el0));

	if (has_vhe())
		return;

	if (cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_PMSVer_SHIFT) &&
	    !(read_sysreg_s(SYS_PMBIDR_EL1) & PMBIDR_EL1_P))
		host_data_set_flag(HAS_SPE);

	if (cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_TraceBuffer_SHIFT) &&
	    !(read_sysreg_s(SYS_TRBIDR_EL1) & TRBIDR_EL1_P))
		host_data_set_flag(HAS_TRBE);
}

void kvm_vcpu_load_debug(struct kvm_vcpu *vcpu)
{
	u64 mdscr;

	/* Must be called before kvm_vcpu_load_vhe() */
	KVM_BUG_ON(vcpu_get_flag(vcpu, SYSREGS_ON_CPU), vcpu->kvm);

	if (vcpu->guest_debug || kvm_vcpu_os_lock_enabled(vcpu)) {
		mdscr = MDSCR_EL1_TDCC;

		/*
		 * Steal the guest's single-step state machine if userspace wants
		 * single-step the guest.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP) {
			mdscr |= MDSCR_EL1_SS;

			if (*vcpu_cpsr(vcpu) & DBG_SPSR_SS)
				vcpu_clear_flag(vcpu, GUEST_SS_ACTIVE_PENDING);
			else
				vcpu_set_flag(vcpu, GUEST_SS_ACTIVE_PENDING);

			if (!vcpu_get_flag(vcpu, HOST_SS_ACTIVE_PENDING))
				*vcpu_cpsr(vcpu) |= DBG_SPSR_SS;
			else
				*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
		}

		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW)
			mdscr |= MDSCR_EL1_MDE;

		vcpu->arch.external_mdscr_el1 = mdscr;
		vcpu->arch.debug_owner = VCPU_DEBUG_HOST_OWNED;
	} else {
		mdscr = vcpu_read_sys_reg(vcpu, MDSCR_EL1);

		/*
		 * Eagerly restore the debug state if the debugger is actively
		 * in use
		 */
		if (mdscr & (MDSCR_EL1_KDE | MDSCR_EL1_MDE))
			vcpu->arch.debug_owner = VCPU_DEBUG_GUEST_OWNED;
		else
			vcpu->arch.debug_owner = VCPU_DEBUG_FREE;
	}

	kvm_arm_setup_mdcr_el2(vcpu);
}

void kvm_vcpu_put_debug(struct kvm_vcpu *vcpu)
{
	if (likely(!(vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)))
		return;

	/*
	 * Save the host's single-step state machine and restore the guest's
	 * before potentially returning to userspace.
	 */
	if (!(*vcpu_cpsr(vcpu) & DBG_SPSR_SS))
		vcpu_set_flag(vcpu, HOST_SS_ACTIVE_PENDING);
	else
		vcpu_clear_flag(vcpu, HOST_SS_ACTIVE_PENDING);

	if (vcpu_get_flag(vcpu, GUEST_SS_ACTIVE_PENDING))
		*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
	else
		*vcpu_cpsr(vcpu) |= DBG_SPSR_SS;
}

void kvm_handle_debug_access(struct kvm_vcpu *vcpu)
{
	if (kvm_host_owns_debug_regs(vcpu))
		return;

	WARN_ON_ONCE(vcpu->arch.debug_owner == VCPU_DEBUG_GUEST_OWNED);
	vcpu->arch.debug_owner = VCPU_DEBUG_GUEST_OWNED;
	kvm_arm_setup_mdcr_el2(vcpu);

	if (has_vhe())
		write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);
}

void kvm_debug_handle_oslar(struct kvm_vcpu *vcpu, u64 val)
{
	if (val & OSLAR_EL1_OSLK)
		__vcpu_sys_reg(vcpu, OSLSR_EL1) |= OSLSR_EL1_OSLK;
	else
		__vcpu_sys_reg(vcpu, OSLSR_EL1) &= ~OSLSR_EL1_OSLK;

	preempt_disable();
	kvm_arch_vcpu_put(vcpu);
	kvm_arch_vcpu_load(vcpu, smp_processor_id());
	preempt_enable();
}
