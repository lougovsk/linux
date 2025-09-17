/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_FUTEX_H
#define __ASM_FUTEX_H

#include <linux/futex.h>
#include <linux/uaccess.h>
#include <linux/stringify.h>

#include <asm/alternative.h>
#include <asm/alternative-macros.h>
#include <asm/errno.h>

#define FUTEX_MAX_LOOPS	128 /* What's the largest number you can think of? */

#define LLSC_FUTEX_ATOMIC_OP(op, insn)					\
static __always_inline int						\
__llsc_futex_atomic_##op(int oparg, u32 __user *uaddr, int *oval)	\
{									\
	unsigned int loops = FUTEX_MAX_LOOPS;				\
	int ret, oldval, tmp;						\
									\
	uaccess_enable_privileged();					\
	asm volatile("// __llsc_futex_atomic_" #op "\n"			\
"	prfm	pstl1strm, %2\n"					\
"1:	ldxr	%w1, %2\n"						\
	insn "\n"							\
"2:	stlxr	%w0, %w3, %2\n"						\
"	cbz	%w0, 3f\n"						\
"	sub	%w4, %w4, %w0\n"					\
"	cbnz	%w4, 1b\n"						\
"	mov	%w0, %w6\n"						\
"3:\n"									\
"	dmb	ish\n"							\
	_ASM_EXTABLE_UACCESS_ERR(1b, 3b, %w0)				\
	_ASM_EXTABLE_UACCESS_ERR(2b, 3b, %w0)				\
	: "=&r" (ret), "=&r" (oldval), "+Q" (*uaddr), "=&r" (tmp),	\
	  "+r" (loops)							\
	: "r" (oparg), "Ir" (-EAGAIN)					\
	: "memory");							\
	uaccess_disable_privileged();					\
									\
	if (!ret)							\
		*oval = oldval;						\
									\
	return ret;							\
}

LLSC_FUTEX_ATOMIC_OP(add, "add	%w3, %w1, %w5")
LLSC_FUTEX_ATOMIC_OP(or,  "orr	%w3, %w1, %w5")
LLSC_FUTEX_ATOMIC_OP(and, "and	%w3, %w1, %w5")
LLSC_FUTEX_ATOMIC_OP(eor, "eor	%w3, %w1, %w5")
LLSC_FUTEX_ATOMIC_OP(set, "mov	%w3, %w5")

static __always_inline int
__llsc_futex_cmpxchg(u32 __user *uaddr, u32 oldval, u32 newval, u32 *oval)
{
	int ret = 0;
	unsigned int loops = FUTEX_MAX_LOOPS;
	u32 val, tmp;

	uaccess_enable_privileged();
	asm volatile("//__llsc_futex_cmpxchg\n"
"	prfm	pstl1strm, %2\n"
"1:	ldxr	%w1, %2\n"
"	eor	%w3, %w1, %w5\n"
"	cbnz	%w3, 4f\n"
"2:	stlxr	%w3, %w6, %2\n"
"	cbz	%w3, 3f\n"
"	sub	%w4, %w4, %w3\n"
"	cbnz	%w4, 1b\n"
"	mov	%w0, %w7\n"
"3:\n"
"	dmb	ish\n"
"4:\n"
	_ASM_EXTABLE_UACCESS_ERR(1b, 4b, %w0)
	_ASM_EXTABLE_UACCESS_ERR(2b, 4b, %w0)
	: "+r" (ret), "=&r" (val), "+Q" (*uaddr), "=&r" (tmp), "+r" (loops)
	: "r" (oldval), "r" (newval), "Ir" (-EAGAIN)
	: "memory");
	uaccess_disable_privileged();

	if (!ret)
		*oval = val;

	return ret;
}

#ifdef CONFIG_AS_HAS_LSUI

/*
 * When the LSUI feature is present, the CPU also implements PAN, because
 * FEAT_PAN has been mandatory since Armv8.1. Therefore, there is no need to
 * call uaccess_ttbr0_enable()/uaccess_ttbr0_disable() around each LSUI
 * operation.
 */

#define __LSUI_PREAMBLE	".arch_extension lsui\n"

#define LSUI_FUTEX_ATOMIC_OP(op, asm_op, mb)				\
static __always_inline int						\
__lsui_futex_atomic_##op(int oparg, u32 __user *uaddr, int *oval)	\
{									\
	int ret = 0;							\
	int oldval;							\
									\
	asm volatile("// __lsui_futex_atomic_" #op "\n"			\
	__LSUI_PREAMBLE							\
"1:	" #asm_op #mb "	%w3, %w2, %1\n"					\
"2:\n"									\
	_ASM_EXTABLE_UACCESS_ERR(1b, 2b, %w0)				\
	: "+r" (ret), "+Q" (*uaddr), "=r" (oldval)			\
	: "r" (oparg)							\
	: "memory");							\
									\
	if (!ret)							\
		*oval = oldval;						\
									\
	return ret;							\
}

LSUI_FUTEX_ATOMIC_OP(add, ldtadd, al)
LSUI_FUTEX_ATOMIC_OP(or, ldtset, al)
LSUI_FUTEX_ATOMIC_OP(andnot, ldtclr, al)
LSUI_FUTEX_ATOMIC_OP(set, swpt, al)

static __always_inline int
__lsui_cmpxchg64(u64 __user *uaddr, u64 *oldval, u64 newval)
{
	int ret = 0;

	asm volatile("// __lsui_cmpxchg64\n"
	__LSUI_PREAMBLE
"1:	casalt	%x2, %x3, %1\n"
"2:\n"
	_ASM_EXTABLE_UACCESS_ERR(1b, 2b, %w0)
	: "+r" (ret), "+Q" (*uaddr), "+r" (*oldval)
	: "r" (newval)
	: "memory");

	return ret;
}

static __always_inline int
__lsui_cmpxchg32(u32 __user *uaddr, u32 oldval, u32 newval, u32 *oval)
{
	u64 __user *uaddr_al;
	u64 oval64, nval64, tmp;
	static const u64 hi_mask = IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ?
		GENMASK_U64(63, 32): GENMASK_U64(31, 0);
	static const u8 hi_shift = IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ? 32 : 0;
	static const u8 lo_shift = IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ? 0 : 32;

	uaddr_al = (u64 __user *) PTR_ALIGN_DOWN(uaddr, sizeof(u64));
	if (get_user(oval64, uaddr_al))
		return -EFAULT;

	if ((u32 __user *)uaddr_al != uaddr) {
		nval64 = ((oval64 & ~hi_mask) | ((u64)newval << hi_shift));
		oval64 = ((oval64 & ~hi_mask) | ((u64)oldval << hi_shift));
	} else {
		nval64 = ((oval64 & hi_mask) | ((u64)newval << lo_shift));
		oval64 = ((oval64 & hi_mask) | ((u64)oldval << lo_shift));
	}

	tmp = oval64;

	if (__lsui_cmpxchg64(uaddr_al, &oval64, nval64))
		return -EFAULT;

	if (tmp != oval64)
		return -EAGAIN;

	*oval = oldval;

	return 0;
}

static __always_inline int
__lsui_futex_atomic_and(int oparg, u32 __user *uaddr, int *oval)
{
	return __lsui_futex_atomic_andnot(~oparg, uaddr, oval);
}

static __always_inline int
__lsui_futex_atomic_eor(int oparg, u32 __user *uaddr, int *oval)
{
	u32 oldval, newval;

	/*
	 * there are no ldteor/stteor instructions...
	 */
	if (get_user(oldval, uaddr))
		return -EFAULT;

	newval = oldval ^ oparg;

	return __lsui_cmpxchg32(uaddr, oldval, newval, oval);

}

static __always_inline int
__lsui_futex_cmpxchg(u32 __user *uaddr, u32 oldval, u32 newval, u32 *oval)
{
	return __lsui_cmpxchg32(uaddr, oldval, newval, oval);
}

#define __lsui_llsc_body(op, ...)					\
({									\
	alternative_has_cap_likely(ARM64_HAS_LSUI) ?			\
		__lsui_##op(__VA_ARGS__) : __llsc_##op(__VA_ARGS__);	\
})

#else	/* CONFIG_AS_HAS_LSUI */

#define __lsui_llsc_body(op, ...)	__llsc_##op(__VA_ARGS__)

#endif	/* CONFIG_AS_HAS_LSUI */


#define FUTEX_ATOMIC_OP(op)						\
static __always_inline int						\
__futex_atomic_##op(int oparg, u32 __user *uaddr, int *oval)		\
{									\
	return __lsui_llsc_body(futex_atomic_##op, oparg, uaddr, oval);	\
}

FUTEX_ATOMIC_OP(add)
FUTEX_ATOMIC_OP(or)
FUTEX_ATOMIC_OP(and)
FUTEX_ATOMIC_OP(eor)
FUTEX_ATOMIC_OP(set)

static __always_inline int
__futex_cmpxchg(u32 __user *uaddr, u32 oldval, u32 newval, u32 *oval)
{
	return __llsc_futex_cmpxchg(uaddr, oldval, newval, oval);
}

static inline int
arch_futex_atomic_op_inuser(int op, int oparg, int *oval, u32 __user *_uaddr)
{
	int ret;
	u32 __user *uaddr;

	if (!access_ok(_uaddr, sizeof(u32)))
		return -EFAULT;

	uaddr = __uaccess_mask_ptr(_uaddr);

	switch (op) {
	case FUTEX_OP_SET:
		ret = __futex_atomic_set(oparg, uaddr, oval);
		break;
	case FUTEX_OP_ADD:
		ret = __futex_atomic_add(oparg, uaddr, oval);
		break;
	case FUTEX_OP_OR:
		ret = __futex_atomic_or(oparg, uaddr, oval);
		break;
	case FUTEX_OP_ANDN:
		ret = __futex_atomic_and(~oparg, uaddr, oval);
		break;
	case FUTEX_OP_XOR:
		ret = __futex_atomic_eor(oparg, uaddr, oval);
		break;
	default:
		ret = -ENOSYS;
	}

	return ret;
}

static inline int
futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *_uaddr,
			      u32 oldval, u32 newval)
{
	u32 __user *uaddr;

	if (!access_ok(_uaddr, sizeof(u32)))
		return -EFAULT;

	uaddr = __uaccess_mask_ptr(_uaddr);

	return __futex_cmpxchg(uaddr, oldval, newval, uval);
}

#endif /* __ASM_FUTEX_H */
