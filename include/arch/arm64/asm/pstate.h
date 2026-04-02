/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PSTATE_H
#define __ASM_PSTATE_H

#include <asm/sysreg-defs.h>
#ifdef __arm64__
#include <uapi/asm/pstate.h>
#else
#include <uapi/arch/arm64/asm/pstate.h>
#endif // __arm64__

/* Additional SPSR bits not exposed in the UABI */
#define PSR_MODE_THREAD_BIT	BIT(0)
#define PSR_IL_BIT		SPSR_IL

/* SPSR_ELx bits for exceptions taken from AArch32 */
#define PSR_AA32_MODE_MASK	SPSR_MODE_MASK
#define PSR_AA32_MODE_USR	(SPSR_MODE_32BIT | SPSR32_MODE_USR)
#define PSR_AA32_MODE_FIQ	(SPSR_MODE_32BIT | SPSR32_MODE_FIQ)
#define PSR_AA32_MODE_IRQ	(SPSR_MODE_32BIT | SPSR32_MODE_IRQ)
#define PSR_AA32_MODE_SVC	(SPSR_MODE_32BIT | SPSR32_MODE_SVC)
#define PSR_AA32_MODE_ABT	(SPSR_MODE_32BIT | SPSR32_MODE_ABT)
#define PSR_AA32_MODE_HYP	(SPSR_MODE_32BIT | SPSR32_MODE_HYP)
#define PSR_AA32_MODE_UND	(SPSR_MODE_32BIT | SPSR32_MODE_UND)
#define PSR_AA32_MODE_SYS	(SPSR_MODE_32BIT | SPSR32_MODE_SYS)
#define PSR_AA32_T_BIT		SPSR32_T
#define PSR_AA32_F_BIT		SPSR_F
#define PSR_AA32_I_BIT		SPSR_I
#define PSR_AA32_A_BIT		SPSR_A
#define PSR_AA32_E_BIT		SPSR32_E
#define PSR_AA32_PAN_BIT	SPSR_PAN
#define PSR_AA32_SSBS_BIT	SPSR32_SSBS
#define PSR_AA32_DIT_BIT	SPSR_DIT
#define PSR_AA32_Q_BIT		SPSR32_Q
#define PSR_AA32_V_BIT		SPSR_V
#define PSR_AA32_C_BIT		SPSR_C
#define PSR_AA32_Z_BIT		SPSR_Z
#define PSR_AA32_N_BIT		SPSR_N
#define PSR_AA32_IT_MASK	SPSR32_IT_MASK	/* If-Then execution state mask */
#define PSR_AA32_GE_MASK	SPSR32_GE_MASK

/* AArch32 CPSR bits, as seen in AArch32 */
#define COMPAT_PSR_DIT_BIT	0x00200000

#endif /* __ASM_PSTATE_H */
