/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017 ARM Ltd.
 */
#ifndef __ASM_EXCEPTION_MASKS_H
#define __ASM_EXCEPTION_MASKS_H

#include <linux/irqflags.h>

#include <asm/arch_gicv3.h>
#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/ptrace.h>

/*
 * Logical exception mask: tracks the three independent exception
 * masking controls on arm64:
 *  - DAIF (PSTATE.{D,A,I,F} bits)
 *  - PMR  (ICC_PMR_EL1)
 *  - ALLINT (PSTATE.ALLINT)
 */
struct exception_mask {
	unsigned long daif;
	unsigned long pmr;
	unsigned long allint;		// for future FEAT_NMI use
};

static inline struct exception_mask arm64_make_procctx_mask(void)
{
	struct exception_mask mask;

	mask.daif = DAIF_PROCCTX;
	if (system_uses_irq_prio_masking())
		mask.pmr = GIC_PRIO_IRQON;

	mask.allint = 0;

	return mask;
}

static inline struct exception_mask arm64_make_errctx_mask(void)
{
	struct exception_mask mask;

	mask.daif = DAIF_ERRCTX;
	if (system_uses_irq_prio_masking())
		mask.pmr = GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET;

	mask.allint = 0;

	return mask;
}

static inline struct exception_mask arm64_make_noirq_mask(void)
{
	struct exception_mask mask;

	if (system_uses_irq_prio_masking()) {
		mask.daif = 0;
		mask.pmr = GIC_PRIO_IRQOFF;
	} else
		mask.daif = DAIF_PROCCTX_NOIRQ;

	mask.allint = 0;

	return mask;
}

/* Mask all exceptions immediately */
static inline void local_exception_mask(void)
{
	WARN_ON(system_has_prio_mask_debugging() &&
		(read_sysreg_s(SYS_ICC_PMR_EL1) == (GIC_PRIO_IRQOFF |
						    GIC_PRIO_PSR_I_SET)));

	asm volatile("msr daifset, #0xf" ::: "memory");

	if (system_uses_irq_prio_masking())
		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);

	trace_hardirqs_off();
}

static inline void local_exception_save_mask(struct exception_mask *mask)
{
	mask->daif = read_sysreg(daif);
	if (system_uses_irq_prio_masking())
		mask->pmr = gic_read_pmr();

	mask->allint = 0;
}

static inline struct exception_mask local_exception_save_and_mask(void)
{
	struct exception_mask mask;

	local_exception_save_mask(&mask);
	local_exception_mask();

	return mask;
}

static inline void local_exception_restore(const struct exception_mask mask)
{
	bool irq_disabled = mask.daif & PSR_I_BIT;

	if (system_uses_irq_prio_masking())
		irq_disabled |= (mask.pmr == GIC_PRIO_IRQOFF);

	WARN_ON(system_has_prio_mask_debugging() &&
		(read_sysreg(daif) & DAIF_PROCCTX_NOIRQ) != DAIF_PROCCTX_NOIRQ);

	if (!irq_disabled)
		trace_hardirqs_on();

	if (system_uses_irq_prio_masking()) {
		gic_write_pmr(mask.pmr);
		pmr_sync();
	}

	write_sysreg(mask.daif, daif);

	if (irq_disabled)
		trace_hardirqs_off();
}

/*
 * Called by synchronous exception handlers to restore the DAIF bits that were
 * modified by taking an exception.
 */
static inline void local_exception_inherit(struct pt_regs *regs)
{
	if (!regs_irqs_disabled(regs))
		trace_hardirqs_on();

	if (system_uses_irq_prio_masking())
		gic_write_pmr(regs->pmr);

	write_sysreg(regs->pstate & DAIF_MASK, daif);
}

/*
 * Allow Debug exceptions and SError, mask IRQ/FIQ
 */
static __always_inline struct exception_mask irq_entry_unmask_debug_serror(struct pt_regs *regs)
{
	struct exception_mask orig;

	local_exception_save_mask(&orig);
	write_sysreg(DAIF_PROCCTX_NOIRQ, daif);

	return orig;
}

static __always_inline struct exception_mask error_entry_unmask_debug(struct pt_regs *regs)
{
	struct exception_mask orig;

	local_exception_save_mask(&orig);
	local_exception_restore(arm64_make_errctx_mask());

	return orig;
}

static __always_inline struct exception_mask el1_sync_entry_unmask_inherit(struct pt_regs *regs)
{
	struct exception_mask orig;

	local_exception_save_mask(&orig);
	local_exception_inherit(regs);

	return orig;
}

/*
 * Unmask all exceptions to establish a standard process context.
 * Suitable for EL0 sync entry and secondary CPU boot streaming.
 */
static __always_inline void el0_sync_entry_unmask_all(struct pt_regs *regs)
{
	local_exception_restore(arm64_make_procctx_mask());
}

/*
 * Retained for symmetric naming, used before returning to EL0
 */
static __always_inline void el0_sync_exit_unmask_all(struct pt_regs *regs)
{
	local_exception_restore(arm64_make_procctx_mask());
}

/*
 * Mask all exceptions, ready to return to interrupted context
 */
static __always_inline void exception_exit_restore_mask(struct exception_mask mask)
{
	write_sysreg(mask.daif, daif);
}

static inline void local_exception_restore_noirq(void)
{
	local_exception_restore(arm64_make_noirq_mask());
}

static inline void local_exception_restore_errctx(void)
{
	local_exception_restore(arm64_make_errctx_mask());
}

static inline void local_exception_restore_procctx(void)
{
	local_exception_restore(arm64_make_procctx_mask());
}
#endif /* __ASM_EXCEPTION_MASKS_H */
