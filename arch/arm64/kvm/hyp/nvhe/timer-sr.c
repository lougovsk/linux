// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012-2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <clocksource/arm_arch_timer.h>
#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <nvhe/pkvm.h>

static u32 timer_freq;

void __kvm_timer_set_cntvoff(u64 cntvoff)
{
	write_sysreg(cntvoff, cntvoff_el2);
}

/*
 * Should only be called on non-VHE or hVHE setups.
 * VHE systems use EL2 timers and configure EL1 timers in kvm_timer_init_vhe().
 */
void __timer_disable_traps(struct kvm_vcpu *vcpu)
{
	u64 set, clr, shift = 0;

	if (has_hvhe())
		shift = 10;

	/* Allow physical timer/counter access for the host */
	set = (CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN) << shift;
	clr = CNTHCTL_EL1TVT | CNTHCTL_EL1TVCT;

	sysreg_clear_set(cnthctl_el2, clr, set);
}

/*
 * Should only be called on non-VHE or hVHE setups.
 * VHE systems use EL2 timers and configure EL1 timers in kvm_timer_init_vhe().
 */
void __timer_enable_traps(struct kvm_vcpu *vcpu)
{
	u64 clr = 0, set = 0;

	/*
	 * Disallow physical timer access for the guest
	 * Physical counter access is allowed if no offset is enforced
	 * or running protected (we don't offset anything in this case).
	 */
	clr = CNTHCTL_EL1PCEN;
	if (is_protected_kvm_enabled() ||
	    !kern_hyp_va(vcpu->kvm)->arch.timer_data.poffset)
		set |= CNTHCTL_EL1PCTEN;
	else
		clr |= CNTHCTL_EL1PCTEN;

	if (has_hvhe()) {
		clr <<= 10;
		set <<= 10;
	}

	/*
	 * Trap the virtual counter/timer if we have a broken cntvoff
	 * implementation.
	 */
	if (has_broken_cntvoff())
		set |= CNTHCTL_EL1TVT | CNTHCTL_EL1TVCT;

	sysreg_clear_set(cnthctl_el2, clr, set);
}

static u64 pkvm_ticks_get(void)
{
	return __arch_counter_get_cntvct();
}

#define SEC_TO_US 1000000

int pkvm_timer_init(void)
{
	timer_freq = read_sysreg(cntfrq_el0);
	/*
	 * TODO: The highest privileged level is supposed to initialize this
	 * register. But on some systems (which?), this information is only
	 * contained in the device-tree, so we'll need to find it out some other
	 * way.
	 */
	if (!timer_freq || timer_freq < SEC_TO_US)
		return -ENODEV;
	return 0;
}

#define pkvm_time_ticks_to_us(ticks) ((u64)(ticks) * SEC_TO_US / timer_freq)

/* Return time in us. */
u64 pkvm_time_get(void)
{
	return pkvm_time_ticks_to_us(pkvm_ticks_get());
}
