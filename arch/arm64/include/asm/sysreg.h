/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Macros for accessing system registers with older binutils.
 *
 * Copyright (C) 2014 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#ifndef __ASM_SYSREG_H
#define __ASM_SYSREG_H

#include <linux/bits.h>
#include <linux/stringify.h>
#include <linux/kasan-tags.h>
#include <linux/kconfig.h>

#include <asm/gpr-num.h>
#include <asm/sysreg-defs.h>

#ifndef CONFIG_BROKEN_GAS_INST

#ifdef __ASSEMBLER__
// The space separator is omitted so that __emit_inst(x) can be parsed as
// either an assembler directive or an assembler macro argument.
#define __emit_inst(x)			.inst(x)
#else
#define __emit_inst(x)			".inst " __stringify((x)) "\n\t"
#endif

#else  /* CONFIG_BROKEN_GAS_INST */

#ifndef CONFIG_CPU_BIG_ENDIAN
#define __INSTR_BSWAP(x)		(x)
#else  /* CONFIG_CPU_BIG_ENDIAN */
#define __INSTR_BSWAP(x)		((((x) << 24) & 0xff000000)	| \
					 (((x) <<  8) & 0x00ff0000)	| \
					 (((x) >>  8) & 0x0000ff00)	| \
					 (((x) >> 24) & 0x000000ff))
#endif	/* CONFIG_CPU_BIG_ENDIAN */

#ifdef __ASSEMBLER__
#define __emit_inst(x)			.long __INSTR_BSWAP(x)
#else  /* __ASSEMBLER__ */
#define __emit_inst(x)			".long " __stringify(__INSTR_BSWAP(x)) "\n\t"
#endif	/* __ASSEMBLER__ */

#endif	/* CONFIG_BROKEN_GAS_INST */

#define SET_PSTATE_PAN(x)		SET_PSTATE((x), PAN)
#define SET_PSTATE_UAO(x)		SET_PSTATE((x), UAO)
#define SET_PSTATE_SSBS(x)		SET_PSTATE((x), SSBS)
#define SET_PSTATE_DIT(x)		SET_PSTATE((x), DIT)
#define SET_PSTATE_TCO(x)		SET_PSTATE((x), TCO)

#define set_pstate_pan(x)		asm volatile(SET_PSTATE_PAN(x))
#define set_pstate_uao(x)		asm volatile(SET_PSTATE_UAO(x))
#define set_pstate_ssbs(x)		asm volatile(SET_PSTATE_SSBS(x))
#define set_pstate_dit(x)		asm volatile(SET_PSTATE_DIT(x))

/* Register-based PAN access, for save/restore purposes */
#define SYS_PSTATE_PAN			sys_reg(3, 0, 4, 2, 3)

#define __SYS_BARRIER_INSN(op0, op1, CRn, CRm, op2, Rt)			\
	__emit_inst(0xd5000000					|	\
		    sys_insn((op0), (op1), (CRn), (CRm), (op2))	|	\
		    ((Rt) & 0x1f))

#define SB_BARRIER_INSN			__SYS_BARRIER_INSN(0, 3, 3, 0, 7, 31)
#define GSB_SYS_BARRIER_INSN		__SYS_BARRIER_INSN(1, 0, 12, 0, 0, 31)
#define GSB_ACK_BARRIER_INSN		__SYS_BARRIER_INSN(1, 0, 12, 0, 1, 31)

#ifdef CONFIG_CPU_BIG_ENDIAN
#define ENDIAN_SET_EL2		SCTLR_ELx_EE
#else
#define ENDIAN_SET_EL2		0
#endif

#define INIT_SCTLR_EL2_MMU_ON						\
	(SCTLR_ELx_M  | SCTLR_ELx_C | SCTLR_ELx_SA | SCTLR_ELx_I |	\
	 SCTLR_ELx_IESB | SCTLR_ELx_WXN | ENDIAN_SET_EL2 |		\
	 SCTLR_ELx_ITFSB | SCTLR_EL2_RES1)

#define INIT_SCTLR_EL2_MMU_OFF \
	(SCTLR_EL2_RES1 | ENDIAN_SET_EL2)

/* SCTLR_EL1 specific flags. */
#ifdef CONFIG_CPU_BIG_ENDIAN
#define ENDIAN_SET_EL1		(SCTLR_EL1_E0E | SCTLR_ELx_EE)
#else
#define ENDIAN_SET_EL1		0
#endif

#define INIT_SCTLR_EL1_MMU_OFF \
	(ENDIAN_SET_EL1 | SCTLR_EL1_LSMAOE | SCTLR_EL1_nTLSMD | \
	 SCTLR_EL1_EIS  | SCTLR_EL1_TSCXT  | SCTLR_EL1_EOS)

#define INIT_SCTLR_EL1_MMU_ON \
	(SCTLR_ELx_M      | SCTLR_ELx_C      | SCTLR_ELx_SA    | \
	 SCTLR_EL1_SA0    | SCTLR_EL1_SED    | SCTLR_ELx_I     | \
	 SCTLR_EL1_DZE    | SCTLR_EL1_UCT    | SCTLR_EL1_nTWE  | \
	 SCTLR_ELx_IESB   | SCTLR_EL1_SPAN   | SCTLR_ELx_ITFSB | \
	 ENDIAN_SET_EL1   | SCTLR_EL1_UCI    | SCTLR_EL1_EPAN  | \
	 SCTLR_EL1_LSMAOE | SCTLR_EL1_nTLSMD | SCTLR_EL1_EIS   | \
	 SCTLR_EL1_TSCXT  | SCTLR_EL1_EOS)

#ifdef CONFIG_ARM64_PA_BITS_52
#define ID_AA64MMFR0_EL1_PARANGE_MAX	ID_AA64MMFR0_EL1_PARANGE_52
#else
#define ID_AA64MMFR0_EL1_PARANGE_MAX	ID_AA64MMFR0_EL1_PARANGE_48
#endif

#if defined(CONFIG_ARM64_4K_PAGES)
#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN4_SHIFT
#define ID_AA64MMFR0_EL1_TGRAN_LPA2		ID_AA64MMFR0_EL1_TGRAN4_52_BIT
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MIN
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN4_SUPPORTED_MAX
#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN4_2_SHIFT
#elif defined(CONFIG_ARM64_16K_PAGES)
#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN16_SHIFT
#define ID_AA64MMFR0_EL1_TGRAN_LPA2		ID_AA64MMFR0_EL1_TGRAN16_52_BIT
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MIN
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN16_SUPPORTED_MAX
#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN16_2_SHIFT
#elif defined(CONFIG_ARM64_64K_PAGES)
#define ID_AA64MMFR0_EL1_TGRAN_SHIFT		ID_AA64MMFR0_EL1_TGRAN64_SHIFT
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN	ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MIN
#define ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX	ID_AA64MMFR0_EL1_TGRAN64_SUPPORTED_MAX
#define ID_AA64MMFR0_EL1_TGRAN_2_SHIFT		ID_AA64MMFR0_EL1_TGRAN64_2_SHIFT
#endif

#ifdef CONFIG_KASAN_HW_TAGS
/*
 * KASAN always uses a whole byte for its tags. With CONFIG_KASAN_HW_TAGS it
 * only uses tags in the range 0xF0-0xFF, which we map to MTE tags 0x0-0xF.
 */
#define __MTE_TAG_MIN		(KASAN_TAG_MIN & 0xf)
#define __MTE_TAG_MAX		(KASAN_TAG_MAX & 0xf)
#define __MTE_TAG_INCL		GENMASK(__MTE_TAG_MAX, __MTE_TAG_MIN)
#define KERNEL_GCR_EL1_EXCL	(SYS_GCR_EL1_EXCL_MASK & ~__MTE_TAG_INCL)
#else
#define KERNEL_GCR_EL1_EXCL	SYS_GCR_EL1_EXCL_MASK
#endif

#define KERNEL_GCR_EL1		(SYS_GCR_EL1_RRND | KERNEL_GCR_EL1_EXCL)

#ifdef __ASSEMBLER__

	.macro	mrs_s, rt, sreg
	 __emit_inst(0xd5200000|(\sreg)|(.L__gpr_num_\rt))
	.endm

	.macro	msr_s, sreg, rt
	__emit_inst(0xd5000000|(\sreg)|(.L__gpr_num_\rt))
	.endm

	.macro	msr_hcr_el2, reg
#if IS_ENABLED(CONFIG_AMPERE_ERRATUM_AC04_CPU_23)
	dsb	nsh
	msr	hcr_el2, \reg
	isb
#else
	msr	hcr_el2, \reg
#endif
	.endm
#else

#include <linux/bitfield.h>
#include <linux/build_bug.h>
#include <linux/types.h>
#include <asm/alternative.h>

#define DEFINE_MRS_S						\
	__DEFINE_ASM_GPR_NUMS					\
"	.macro	mrs_s, rt, sreg\n"				\
	__emit_inst(0xd5200000|(\\sreg)|(.L__gpr_num_\\rt))	\
"	.endm\n"

#define DEFINE_MSR_S						\
	__DEFINE_ASM_GPR_NUMS					\
"	.macro	msr_s, sreg, rt\n"				\
	__emit_inst(0xd5000000|(\\sreg)|(.L__gpr_num_\\rt))	\
"	.endm\n"

#define UNDEFINE_MRS_S						\
"	.purgem	mrs_s\n"

#define UNDEFINE_MSR_S						\
"	.purgem	msr_s\n"

#define __mrs_s(v, r)						\
	DEFINE_MRS_S						\
"	mrs_s " v ", " __stringify(r) "\n"			\
	UNDEFINE_MRS_S

#define __msr_s(r, v)						\
	DEFINE_MSR_S						\
"	msr_s " __stringify(r) ", " v "\n"			\
	UNDEFINE_MSR_S

/*
 * Unlike read_cpuid, calls to read_sysreg are never expected to be
 * optimized away or replaced with synthetic values.
 */
#define read_sysreg(r) ({					\
	u64 __val;						\
	asm volatile("mrs %0, " __stringify(r) : "=r" (__val));	\
	__val;							\
})

/*
 * The "Z" constraint normally means a zero immediate, but when combined with
 * the "%x0" template means XZR.
 */
#define write_sysreg(v, r) do {					\
	u64 __val = (u64)(v);					\
	asm volatile("msr " __stringify(r) ", %x0"		\
		     : : "rZ" (__val));				\
} while (0)

/*
 * For registers without architectural names, or simply unsupported by
 * GAS.
 *
 * __check_r forces warnings to be generated by the compiler when
 * evaluating r which wouldn't normally happen due to being passed to
 * the assembler via __stringify(r).
 */
#define read_sysreg_s(r) ({						\
	u64 __val;							\
	u32 __maybe_unused __check_r = (u32)(r);			\
	asm volatile(__mrs_s("%0", r) : "=r" (__val));			\
	__val;								\
})

/*
 * The "Z" constraint combined with the "%x0" template should be enough
 * to force XZR generation if (v) is a constant 0 value but LLVM does not
 * yet understand that modifier/constraint combo so a conditional is required
 * to nudge the compiler into using XZR as a source for a 0 constant value.
 */
#define write_sysreg_s(v, r) do {					\
	u64 __val = (u64)(v);						\
	u32 __maybe_unused __check_r = (u32)(r);			\
	if (__builtin_constant_p(__val) && __val == 0)			\
		asm volatile(__msr_s(r, "xzr"));			\
	else								\
		asm volatile(__msr_s(r, "%x0") : : "r" (__val));	\
} while (0)

/*
 * Modify bits in a sysreg. Bits in the clear mask are zeroed, then bits in the
 * set mask are set. Other bits are left as-is.
 */
#define sysreg_clear_set(sysreg, clear, set) do {			\
	u64 __scs_val = read_sysreg(sysreg);				\
	u64 __scs_new = (__scs_val & ~(u64)(clear)) | (set);		\
	if (__scs_new != __scs_val)					\
		write_sysreg(__scs_new, sysreg);			\
} while (0)

#define sysreg_clear_set_hcr(clear, set) do {				\
	u64 __scs_val = read_sysreg(hcr_el2);				\
	u64 __scs_new = (__scs_val & ~(u64)(clear)) | (set);		\
	if (__scs_new != __scs_val)					\
		write_sysreg_hcr(__scs_new);			\
} while (0)

#define sysreg_clear_set_s(sysreg, clear, set) do {			\
	u64 __scs_val = read_sysreg_s(sysreg);				\
	u64 __scs_new = (__scs_val & ~(u64)(clear)) | (set);		\
	if (__scs_new != __scs_val)					\
		write_sysreg_s(__scs_new, sysreg);			\
} while (0)

#define write_sysreg_hcr(__val) do {					\
	if (IS_ENABLED(CONFIG_AMPERE_ERRATUM_AC04_CPU_23) &&		\
	   (!system_capabilities_finalized() ||				\
	    alternative_has_cap_unlikely(ARM64_WORKAROUND_AMPERE_AC04_CPU_23))) \
		asm volatile("dsb nsh; msr hcr_el2, %x0; isb"		\
			     : : "rZ" (__val));				\
	else								\
		asm volatile("msr hcr_el2, %x0"				\
			     : : "rZ" (__val));				\
} while (0)

#define read_sysreg_par() ({						\
	u64 par;							\
	asm(ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412));	\
	par = read_sysreg(par_el1);					\
	asm(ALTERNATIVE("nop", "dmb sy", ARM64_WORKAROUND_1508412));	\
	par;								\
})

#endif

#endif	/* __ASM_SYSREG_H */
