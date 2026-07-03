/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_CPUIDLE_H
#define __ASM_CPUIDLE_H

#include <asm/proc-fns.h>

#ifdef CONFIG_ARM64_PSEUDO_NMI
#include <asm/arch_gicv3.h>
#include <asm/exception_masks.h>
#include <asm/ptrace.h>

#define arm_cpuidle_save_irq_context(__m)				\
	do {								\
		struct exception_mask *m = __m;				\
		if (system_uses_irq_prio_masking()) {			\
			local_exception_save_mask(m);			\
			write_sysreg(m->daif | DAIF_PROCCTX_NOIRQ,	\
				     daif);				\
			gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET); \
		}							\
	} while (0)

#define arm_cpuidle_restore_irq_context(__m)				\
	do {								\
		struct exception_mask *m = __m;				\
		if (system_uses_irq_prio_masking()) {			\
			gic_write_pmr(m->pmr);				\
			write_sysreg(m->daif, daif);			\
		}							\
	} while (0)
#else
#define arm_cpuidle_save_irq_context(m)		((void)m)
#define arm_cpuidle_restore_irq_context(m)	((void)m)
#endif
#endif
