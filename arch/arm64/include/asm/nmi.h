/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 ARM Ltd.
 */
#ifndef __ASM_NMI_H
#define __ASM_NMI_H

#ifdef CONFIG_ARM64_NMI
static __always_inline void _allint_clear(void)
{
	asm volatile(__msr_s(SYS_ALLINT_CLR, "xzr"));
}

static __always_inline void _allint_set(void)
{
	asm volatile(__msr_s(SYS_ALLINT_SET, "xzr"));
}
#else
static __always_inline void _allint_clear(void) { }
static __always_inline void _allint_set(void) { }
#endif /* CONFIG_ARM64_NMI */

#endif
