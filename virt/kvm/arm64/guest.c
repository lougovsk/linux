// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/pstate.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>
#include <asm/sigcontext.h>

#include <kvm/arm64/guest.h>

static bool core_reg_offset_is_vreg(u64 off)
{
	return off >= KVM_REG_ARM_CORE_REG(fp_regs.vregs) &&
		off < KVM_REG_ARM_CORE_REG(fp_regs.fpsr);
}

static u64 core_reg_offset_from_id(u64 id)
{
	return id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE);
}

static int core_reg_size_from_offset(const struct kvm_vcpu *vcpu, u64 off)
{
	int size;

	switch (off) {
	case KVM_REG_ARM_CORE_REG(regs.regs[0]) ...
	     KVM_REG_ARM_CORE_REG(regs.regs[30]):
	case KVM_REG_ARM_CORE_REG(regs.sp):
	case KVM_REG_ARM_CORE_REG(regs.pc):
	case KVM_REG_ARM_CORE_REG(regs.pstate):
	case KVM_REG_ARM_CORE_REG(sp_el1):
	case KVM_REG_ARM_CORE_REG(elr_el1):
	case KVM_REG_ARM_CORE_REG(spsr[0]) ...
	     KVM_REG_ARM_CORE_REG(spsr[KVM_NR_SPSR - 1]):
		size = sizeof(__u64);
		break;

	case KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]) ...
	     KVM_REG_ARM_CORE_REG(fp_regs.vregs[31]):
		size = sizeof(__uint128_t);
		break;

	case KVM_REG_ARM_CORE_REG(fp_regs.fpsr):
	case KVM_REG_ARM_CORE_REG(fp_regs.fpcr):
		size = sizeof(__u32);
		break;

	default:
		return -EINVAL;
	}

	if (!IS_ALIGNED(off, size / sizeof(__u32)))
		return -EINVAL;

	/*
	 * The KVM_REG_ARM64_SVE regs must be used instead of
	 * KVM_REG_ARM_CORE for accessing the FPSIMD V-registers on
	 * SVE-enabled vcpus:
	 */
	if (vcpu_has_sve(vcpu) && core_reg_offset_is_vreg(off))
		return -EINVAL;

	return size;
}

static void *core_reg_addr(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	u64 off = core_reg_offset_from_id(reg->id);
	int size = core_reg_size_from_offset(vcpu, off);

	if (size < 0)
		return NULL;

	if (KVM_REG_SIZE(reg->id) != size)
		return NULL;

	switch (off) {
	case KVM_REG_ARM_CORE_REG(regs.regs[0]) ...
	     KVM_REG_ARM_CORE_REG(regs.regs[30]):
		off -= KVM_REG_ARM_CORE_REG(regs.regs[0]);
		off /= 2;
		return &vcpu_gp_regs(vcpu)[off];

	case KVM_REG_ARM_CORE_REG(regs.sp):
		return vcpu_sp_el0(vcpu);

	case KVM_REG_ARM_CORE_REG(regs.pc):
		return vcpu_pc(vcpu);

	case KVM_REG_ARM_CORE_REG(regs.pstate):
		return vcpu_cpsr(vcpu);

	case KVM_REG_ARM_CORE_REG(sp_el1):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1);

	case KVM_REG_ARM_CORE_REG(elr_el1):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1);

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_EL1]):
		return __ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1);

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_ABT]):
		return &vcpu->arch.ctxt.spsr_abt;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_UND]):
		return &vcpu->arch.ctxt.spsr_und;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_IRQ]):
		return &vcpu->arch.ctxt.spsr_irq;

	case KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_FIQ]):
		return &vcpu->arch.ctxt.spsr_fiq;

	case KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]) ...
	     KVM_REG_ARM_CORE_REG(fp_regs.vregs[31]):
		off -= KVM_REG_ARM_CORE_REG(fp_regs.vregs[0]);
		off /= 4;
		return &vcpu->arch.ctxt.fp_regs.vregs[off];

	case KVM_REG_ARM_CORE_REG(fp_regs.fpsr):
		return &vcpu->arch.ctxt.fp_regs.fpsr;

	case KVM_REG_ARM_CORE_REG(fp_regs.fpcr):
		return &vcpu->arch.ctxt.fp_regs.fpcr;

	default:
		return NULL;
	}
}

int get_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/*
	 * Because the kvm_regs structure is a mix of 32, 64 and
	 * 128bit fields, we index it as if it was a 32bit
	 * array. Hence below, nr_regs is the number of entries, and
	 * off the index in the "array".
	 */
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	int nr_regs = sizeof(struct kvm_regs) / sizeof(__u32);
	void *addr;
	u32 off;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	addr = core_reg_addr(vcpu, reg);
	if (!addr)
		return -EINVAL;

	if (copy_to_user(uaddr, addr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

int set_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	int nr_regs = sizeof(struct kvm_regs) / sizeof(__u32);
	__uint128_t tmp;
	void *valp = &tmp, *addr;
	u64 off;
	int err = 0;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	addr = core_reg_addr(vcpu, reg);
	if (!addr)
		return -EINVAL;

	if (KVM_REG_SIZE(reg->id) > sizeof(tmp))
		return -EINVAL;

	if (copy_from_user(valp, uaddr, KVM_REG_SIZE(reg->id))) {
		err = -EFAULT;
		goto out;
	}

	if (off == KVM_REG_ARM_CORE_REG(regs.pstate)) {
		u64 mode = (*(u64 *)valp) & PSR_AA32_MODE_MASK;

		switch (mode) {
		case PSR_AA32_MODE_USR:
			if (!kvm_supports_32bit_el0())
				return -EINVAL;
			break;
		case PSR_AA32_MODE_FIQ:
		case PSR_AA32_MODE_IRQ:
		case PSR_AA32_MODE_SVC:
		case PSR_AA32_MODE_ABT:
		case PSR_AA32_MODE_UND:
		case PSR_AA32_MODE_SYS:
			if (!vcpu_el1_is_32bit(vcpu))
				return -EINVAL;
			break;
		case PSR_MODE_EL2h:
		case PSR_MODE_EL2t:
			if (!vcpu_has_nv(vcpu))
				return -EINVAL;
			fallthrough;
		case PSR_MODE_EL0t:
		case PSR_MODE_EL1t:
		case PSR_MODE_EL1h:
			if (vcpu_el1_is_32bit(vcpu))
				return -EINVAL;
			break;
		default:
			err = -EINVAL;
			goto out;
		}
	}

	memcpy(addr, valp, KVM_REG_SIZE(reg->id));

	if (*vcpu_cpsr(vcpu) & PSR_MODE32_BIT) {
		int i, nr_reg;

		switch (*vcpu_cpsr(vcpu) & PSR_AA32_MODE_MASK) {
		/*
		 * Either we are dealing with user mode, and only the
		 * first 15 registers (+ PC) must be narrowed to 32bit.
		 * AArch32 r0-r14 conveniently map to AArch64 x0-x14.
		 */
		case PSR_AA32_MODE_USR:
		case PSR_AA32_MODE_SYS:
			nr_reg = 15;
			break;

		/*
		 * Otherwise, this is a privileged mode, and *all* the
		 * registers must be narrowed to 32bit.
		 */
		default:
			nr_reg = 31;
			break;
		}

		for (i = 0; i < nr_reg; i++)
			vcpu_set_reg(vcpu, i, (u32)vcpu_get_reg(vcpu, i));

		*vcpu_pc(vcpu) = (u32)*vcpu_pc(vcpu);
	}
out:
	return err;
}

int copy_core_reg_indices(const struct kvm_vcpu *vcpu, u64 __user *uindices)
{
	unsigned int i;
	int n = 0;

	for (i = 0; i < sizeof(struct kvm_regs) / sizeof(__u32); i++) {
		u64 reg = KVM_REG_ARM64 | KVM_REG_ARM_CORE | i;
		int size = core_reg_size_from_offset(vcpu, i);

		if (size < 0)
			continue;

		switch (size) {
		case sizeof(__u32):
			reg |= KVM_REG_SIZE_U32;
			break;

		case sizeof(__u64):
			reg |= KVM_REG_SIZE_U64;
			break;

		case sizeof(__uint128_t):
			reg |= KVM_REG_SIZE_U128;
			break;

		default:
			WARN_ON(1);
			continue;
		}

		if (uindices) {
			if (put_user(reg, uindices))
				return -EFAULT;
			uindices++;
		}

		n++;
	}

	return n;
}

unsigned long num_core_regs(const struct kvm_vcpu *vcpu)
{
	return copy_core_reg_indices(vcpu, NULL);
}
