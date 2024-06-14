/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_CPUIDLE_H
#define __ASM_CPUIDLE_H

#include <asm/proc-fns.h>

#ifdef CONFIG_ARM64_PSEUDO_NMI
#include <asm/daifflags.h>

#define arm_cpuidle_save_irq_context(__c)				\
	do {								\
		arch_irqflags_t *c = __c;				\
		*c = local_allint_save_notrace();			\
	} while (0)

#define arm_cpuidle_restore_irq_context(__c)				\
	do {								\
		arch_irqflags_t *c = __c;				\
		local_allint_restore_notrace(*c);			\
	} while (0)
#else
struct arm_cpuidle_irq_context { };

#define arm_cpuidle_save_irq_context(c)		(void)c
#define arm_cpuidle_restore_irq_context(c)	(void)c
#endif
#endif
