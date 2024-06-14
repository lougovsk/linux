/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017 ARM Ltd.
 */
#ifndef __ASM_DAIFFLAGS_H
#define __ASM_DAIFFLAGS_H

#include <linux/irqflags.h>

#include <asm/arch_gicv3.h>
#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/ptrace.h>

#define DAIF_PROCCTX		0
#define DAIF_PROCCTX_NOIRQ	(PSR_I_BIT | PSR_F_BIT)
#define DAIF_ERRCTX		(PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
#define DAIF_MASK		(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)

/*
 * For Arm64 processor support Armv8.8 or later, kernel supports three types
 * of irqflags, they used for corresponding configuration depicted as below:
 *
 * 1. When CONFIG_ARM64_PSEUDO_NMI and CONFIG_ARM64_NMI are not 'y', kernel
 *    does not support handling NMI.
 *
 * 2. When CONFIG_ARM64_PSEUDO_NMI=y and irqchip.gicv3_pseudo_nmi=1, kernel
 *    makes use of the CPU Interface PMR and GIC priority feature to support
 *    handling NMI.
 *
 * 3. When CONFIG_ARM64_NMI=y and irqchip.gicv3_pseudo_nmi is not enabled,
 *    kernel makes use of the FEAT_NMI extension added since Armv8.8 to
 *    support handling NMI.
 *
 * The table below depicts the relationship between fields in struct
 * arch_irqflags and corresponding interrupt masking behavior reflected in
 * hardware registers.
 *
 * Legend:
 *  IRQ = IRQ and FIQ.
 *  NMI = PSEUDO_NMI or IRQ with superpriority for ARMv8.8.
 *    M = Interrupt is masked.
 *    U = Interrupt is unmasked.
 *    * = Non relevant.
 *
 * IRQ | NMI | SError | ICC_PMR_EL1                       | PSR.DAIF | PSR.ALLINT
 * ------------------------------------------------------------------------------
 *  U  |  U  |   *    | GIC_PRIO_IRQON                    | 0b **00  | 0b 0
 * ------------------------------------------------------------------------------
 *  M  |  U  |   *    | GIC_PRIO_IRQOFF                   | 0b **00  | 0b 0
 * ------------------------------------------------------------------------------
 *  M  |  M  |   *    | (GIC_PRIO_IRQON | GIC_PRIO_I_SET) | 0b **11  | 0b 1
 * ------------------------------------------------------------------------------
 *  M  |  M  |   M    | (GIC_PRIO_IRQON | GIC_PRIO_I_SET) | 0b *111  | 0b 1
 */
union arch_irqflags {
	unsigned long flags;
	struct {
		unsigned long pmr : 8;     // SYS_ICC_PMR_EL1
		unsigned long daif : 10;   // PSTATE.DAIF at bits[6-9]
		unsigned long allint : 14; // PSTATE.ALLINT at bits[13]
	} fields;
};
#define ARCH_IRQFLAGS_INITIALIZER	{ .flags = 0UL }

typedef union arch_irqflags arch_irqflags_t;

static inline void __local_pmr_mask(void)
{
	WARN_ON(system_has_prio_mask_debugging() &&
		(read_sysreg_s(SYS_ICC_PMR_EL1) ==
		 (GIC_PRIO_IRQOFF | GIC_PRIO_PSR_I_SET)));
	/*
	 * Don't really care for a dsb here, we don't intend to enable
	 * IRQs.
	 */
	gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
}

static inline void __local_nmi_mask(void)
{
	msr_pstate_allint(1);
}

static inline void local_allint_mask_notrace(void)
{
	asm volatile ("msr daifset, #0xf" : : : "memory");

	if (system_uses_irq_prio_masking())
		__local_pmr_mask();
	else if (system_uses_nmi())
		__local_nmi_mask();
}

/* mask/save/unmask/restore all exceptions, including interrupts. */
static inline void local_allint_mask(void)
{
	local_allint_mask_notrace();
	trace_hardirqs_off();
}

static inline arch_irqflags_t __local_save_pmr_daif_flags(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.pmr = read_sysreg_s(SYS_ICC_PMR_EL1);
	irqflags.fields.daif = read_sysreg(daif);

	/*
	 * If IRQs are masked with PMR, reflect it in the daif of irqflags.
	 * If NMIs and IRQs are masked with PMR, reflect it in the allint
	 * of irqflags, this avoid the need of checking PSTATE.A in
	 * local_allint_restore() to determine if NMIs are masked.
	 */
	switch (irqflags.fields.pmr) {
	case GIC_PRIO_IRQON:
		irqflags.fields.allint = 0;
		break;

	case __GIC_PRIO_IRQOFF:
	case __GIC_PRIO_IRQOFF_NS:
		irqflags.fields.daif |= PSR_I_BIT | PSR_F_BIT;
		irqflags.fields.allint = 0;
		break;

	case GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET:
		irqflags.fields.daif |= PSR_I_BIT | PSR_F_BIT;
		irqflags.fields.allint = PSR_ALLINT_BIT;
		break;

	default:
		WARN_ON(1);
	}

	return irqflags;
}

static inline arch_irqflags_t __local_save_nmi_daif_flags(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.daif = read_sysreg(daif);
	irqflags.fields.allint = read_sysreg_s(SYS_ALLINT);

	return irqflags;
}

static inline arch_irqflags_t local_allint_save_flags(void)
{
	arch_irqflags_t irqflags = { .flags = 0UL };

	if (system_uses_irq_prio_masking())
		return __local_save_pmr_daif_flags();

	if (system_uses_nmi())
		return __local_save_nmi_daif_flags();

	irqflags.fields.daif = read_sysreg(daif);
	return irqflags;
}

static inline arch_irqflags_t local_allint_save(void)
{
	arch_irqflags_t irqflags;

	irqflags = local_allint_save_flags();

	local_allint_mask();

	return irqflags;
}

static inline void __local_pmr_restore(arch_irqflags_t irqflags)
{
	/*
	 * There has been concern that the write to daif
	 * might be reordered before this write to PMR.
	 * From the ARM ARM DDI 0487D.a, section D1.7.1
	 * "Accessing PSTATE fields":
	 *   Writes to the PSTATE fields have side-effects on
	 *   various aspects of the PE operation. All of these
	 *   side-effects are guaranteed:
	 *     - Not to be visible to earlier instructions in
	 *       the execution stream.
	 *     - To be visible to later instructions in the
	 *       execution stream
	 *
	 * Also, writes to PMR are self-synchronizing, so no
	 * interrupts with a lower priority than PMR is signaled
	 * to the PE after the write.
	 *
	 * So we don't need additional synchronization here.
	 */
	gic_write_pmr(irqflags.fields.pmr);
}

static inline void __local_nmi_restore(arch_irqflags_t irqflags)
{
	msr_pstate_allint(!!irqflags.fields.allint ? 1 : 0);
}

static inline int local_hardirqs_disabled(arch_irqflags_t irqflags)
{
	return irqflags.fields.allint || (irqflags.fields.daif & PSR_I_BIT);
}

static inline void __local_allint_restore(arch_irqflags_t irqflags)
{
	if (system_uses_irq_prio_masking())
		__local_pmr_restore(irqflags);
	else if (system_uses_nmi())
		__local_nmi_restore(irqflags);

	write_sysreg(irqflags.fields.daif, daif);
}

static inline void local_allint_restore_notrace(arch_irqflags_t irqflags)
{
	/*
	 * Use arch_allint.fields.allint to indicates we can take
	 * NMIs, instead of the old hacking style that use PSTATE.A.
	 */
	if (system_uses_irq_prio_masking() && !irqflags.fields.allint)
		irqflags.fields.daif &= ~(PSR_I_BIT | PSR_F_BIT);

	__local_allint_restore(irqflags);
}

/*
 * It has to conside the different kernel configure and parameters, that need
 * to use corresponding operations to mask interrupts properly. For example,
 * the kernel disable PSEUDO_NMI, the kernel uses prio masking to support
 * PSEUDO_NMI, or the kernel uses FEAT_NMI extension to support ARM64_NMI.
 */
static inline void local_allint_restore(arch_irqflags_t irqflags)
{
	int irq_disabled = local_hardirqs_disabled(irqflags);

	if (!irq_disabled)
		trace_hardirqs_on();

	local_allint_restore_notrace(irqflags);

	if (irq_disabled)
		trace_hardirqs_off();
}

/*
 * Called by synchronous exception handlers to restore the DAIF bits that were
 * modified by taking an exception.
 */
static inline void local_allint_inherit(struct pt_regs *regs)
{
	arch_irqflags_t irqflags;

	if (interrupts_enabled(regs))
		trace_hardirqs_on();

	irqflags.fields.pmr = regs->pmr_save;
	irqflags.fields.daif = regs->pstate & DAIF_MASK;
	irqflags.fields.allint = regs->pstate & PSR_ALLINT_BIT;
	__local_allint_restore(irqflags);
}

/*
 * local_nmi_disable - Disable IRQ, FIQ and NMI, with or without superpriority.
 */
static inline void local_nmi_disable(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.daif = DAIF_PROCCTX_NOIRQ;
	irqflags.fields.pmr = GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET;
	irqflags.fields.allint = PSR_ALLINT_BIT;
	__local_allint_restore(irqflags);
}

/*
 * local_irq_mark_enabled - When the kernel enables priority masking,
 * interrupts cannot be handled util ICC_PMR_EL1 is set to GIC_PRIO_IRQON
 * and PSTATE.IF is cleared. This helper function indicates that interrupts
 * remains in a semi-masked state, requring further clearing of PSTATE.IF.
 *
 * Kernel will give a warning, if some function try to enable semi-masked
 * interrupt via the arch_local_irq_enable() defined in <asm/irqflags.h>.
 *
 * This function is typically used before handling the Debug exception.
 */
static inline void local_irq_mark_enabled(void)
{
	if (system_uses_irq_prio_masking())
		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
}

/*
 * local_nmi_serror_disable - Disable all types of interrupt including IRQ,
 * FIQ, Serror and NMI, with or without superpriority.
 */
static inline void local_nmi_serror_disable(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.daif = DAIF_ERRCTX;
	irqflags.fields.pmr = GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET;
	irqflags.fields.allint = PSR_ALLINT_BIT;
	__local_allint_restore(irqflags);
}

/*
 * local_irq_serror_enable - Enable all types of interrupt including IRQ, FIQ,
 * Serror and NMI, with or without superpriority.
 */
static inline void local_irq_serror_enable(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.daif = DAIF_PROCCTX;
	irqflags.fields.pmr = GIC_PRIO_IRQON;
	irqflags.fields.allint = 0;
	__local_allint_restore(irqflags);
}

/*
 * local_nmi_serror_enable - Enable Serror and NMI with or without superpriority.
 */
static inline void local_nmi_serror_enable(void)
{
	arch_irqflags_t irqflags;

	irqflags.fields.daif = DAIF_PROCCTX_NOIRQ;
	irqflags.fields.pmr = GIC_PRIO_IRQOFF;
	irqflags.fields.allint = 0;
	local_allint_restore_notrace(irqflags);
}

/*
 * local_nmi_enable - Enable NMI with or without superpriority.
 */
static inline void local_nmi_enable(void)
{
	if (system_uses_irq_prio_masking()) {
		gic_pmr_mask_irqs();
		asm volatile ("msr daifclr, #3" : : : "memory");
	} else if (system_uses_nmi()) {
		asm volatile ("msr daifset, #3" : : : "memory");
		msr_pstate_allint(0);
	}
}
#endif
