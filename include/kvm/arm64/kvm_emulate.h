/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KVM_ARM64_KVM_EMULATE_H
#define KVM_ARM64_KVM_EMULATE_H

#include <asm/esr.h>
#include <asm/pstate.h>
#include <asm/sysreg-defs.h>

static inline bool kvm_vcpu_is_be(struct kvm_vcpu *vcpu);
static __always_inline unsigned long *vcpu_pc(const struct kvm_vcpu *vcpu);
static __always_inline unsigned long *vcpu_cpsr(const struct kvm_vcpu *vcpu);
static inline bool kvm_vcpu_trap_is_permission_fault(const struct kvm_vcpu *vcpu);
static u64 kvm_vcpu_get_esr(const struct kvm_vcpu *vcpu);
static __always_inline bool vcpu_mode_is_32bit(const struct kvm_vcpu *vcpu);

#define CURRENT_EL_SP_EL0_VECTOR	0x0
#define CURRENT_EL_SP_ELx_VECTOR	0x200
#define LOWER_EL_AArch64_VECTOR		0x400
#define LOWER_EL_AArch32_VECTOR		0x600

enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};

void kvm_skip_instr32(struct kvm_vcpu *vcpu);

void kvm_inject_undefined(struct kvm_vcpu *vcpu);
int kvm_inject_serror_esr(struct kvm_vcpu *vcpu, u64 esr);
int kvm_inject_sea(struct kvm_vcpu *vcpu, bool iabt, u64 addr);
void kvm_inject_size_fault(struct kvm_vcpu *vcpu);

static inline int kvm_inject_sea_dabt(struct kvm_vcpu *vcpu, u64 addr)
{
	return kvm_inject_sea(vcpu, false, addr);
}

static inline int kvm_inject_sea_iabt(struct kvm_vcpu *vcpu, u64 addr)
{
	return kvm_inject_sea(vcpu, true, addr);
}

static inline int kvm_inject_serror(struct kvm_vcpu *vcpu)
{
	/*
	 * ESR_ELx.ISV (later renamed to IDS) indicates whether or not
	 * ESR_ELx.ISS contains IMPLEMENTATION DEFINED syndrome information.
	 *
	 * Set the bit when injecting an SError w/o an ESR to indicate ISS
	 * does not follow the architected format.
	 */
	return kvm_inject_serror_esr(vcpu, ESR_ELx_ISV);
}

void kvm_vcpu_wfi(struct kvm_vcpu *vcpu);

static inline void kvm_skip_instr(struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu)) {
		kvm_skip_instr32(vcpu);
	} else {
		*vcpu_pc(vcpu) += 4;
		*vcpu_cpsr(vcpu) &= ~SPSR64_BTYPE_MASK;
	}

	/* advance the singlestep state machine */
	*vcpu_cpsr(vcpu) &= ~SPSR_SS;
}

/*
 * vcpu_get_reg and vcpu_set_reg should always be passed a register number
 * coming from a read of ESR_EL2. Otherwise, it may give the wrong result on
 * AArch32 with banked registers.
 */
static __always_inline unsigned long vcpu_get_reg(const struct kvm_vcpu *vcpu,
						  u8 reg_num)
{
	return (reg_num == 31) ? 0 : vcpu_gp_regs(vcpu)->regs[reg_num];
}

static __always_inline void vcpu_set_reg(struct kvm_vcpu *vcpu, u8 reg_num,
					 unsigned long val)
{
	if (reg_num != 31)
		vcpu_gp_regs(vcpu)->regs[reg_num] = val;
}

static inline u32 kvm_vcpu_hvc_get_imm(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_esr(vcpu) & ESR_ELx_xVC_IMM_MASK;
}

static __always_inline bool kvm_vcpu_dabt_isvalid(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_ISV);
}

static inline bool kvm_vcpu_dabt_issext(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_SSE);
}

static inline bool kvm_vcpu_dabt_issf(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_SF);
}

static __always_inline int kvm_vcpu_dabt_get_rd(const struct kvm_vcpu *vcpu)
{
	return (kvm_vcpu_get_esr(vcpu) & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
}

static __always_inline bool kvm_vcpu_abt_iss1tw(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_S1PTW);
}

/* Always check for S1PTW *before* using this. */
static __always_inline bool kvm_vcpu_dabt_iswrite(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_esr(vcpu) & ESR_ELx_WNR;
}

static inline bool kvm_vcpu_dabt_is_cm(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_CM);
}

static __always_inline unsigned int kvm_vcpu_dabt_get_as(const struct kvm_vcpu *vcpu)
{
	return 1 << ((kvm_vcpu_get_esr(vcpu) & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
}

/* This one is not specific to Data Abort */
static __always_inline bool kvm_vcpu_trap_il_is32bit(const struct kvm_vcpu *vcpu)
{
	return !!(kvm_vcpu_get_esr(vcpu) & ESR_ELx_IL);
}

static __always_inline u8 kvm_vcpu_trap_get_class(const struct kvm_vcpu *vcpu)
{
	return ESR_ELx_EC(kvm_vcpu_get_esr(vcpu));
}

static inline bool kvm_vcpu_trap_is_iabt(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_IABT_LOW;
}

static inline bool kvm_vcpu_trap_is_exec_fault(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_trap_is_iabt(vcpu) && !kvm_vcpu_abt_iss1tw(vcpu);
}

static __always_inline int kvm_vcpu_sys_get_rt(struct kvm_vcpu *vcpu)
{
	u64 esr = kvm_vcpu_get_esr(vcpu);

	return ESR_ELx_SYS64_ISS_RT(esr);
}

static __always_inline u8 kvm_vcpu_trap_get_fault(const struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_get_esr(vcpu) & ESR_ELx_FSC;
}

static inline bool kvm_is_write_fault(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_abt_iss1tw(vcpu)) {
		/*
		 * Only a permission fault on a S1PTW should be
		 * considered as a write. Otherwise, page tables baked
		 * in a read-only memslot will result in an exception
		 * being delivered in the guest.
		 *
		 * The drawback is that we end-up faulting twice if the
		 * guest is using any of HW AF/DB: a translation fault
		 * to map the page containing the PT (read only at
		 * first), then a permission fault to allow the flags
		 * to be set.
		 */
		return kvm_vcpu_trap_is_permission_fault(vcpu);
	}

	if (kvm_vcpu_trap_is_iabt(vcpu))
		return false;

	return kvm_vcpu_dabt_iswrite(vcpu);
}

static inline unsigned long vcpu_data_guest_to_host(struct kvm_vcpu *vcpu,
						    unsigned long data,
						    unsigned int len)
{
	if (kvm_vcpu_is_be(vcpu)) {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return be16_to_cpu(data & 0xffff);
		case 4:
			return be32_to_cpu(data & 0xffffffff);
		default:
			return be64_to_cpu(data);
		}
	} else {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return le16_to_cpu(data & 0xffff);
		case 4:
			return le32_to_cpu(data & 0xffffffff);
		default:
			return le64_to_cpu(data);
		}
	}

	return data;		/* Leave LE untouched */
}

static inline unsigned long vcpu_data_host_to_guest(struct kvm_vcpu *vcpu,
						    unsigned long data,
						    unsigned int len)
{
	if (kvm_vcpu_is_be(vcpu)) {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return cpu_to_be16(data & 0xffff);
		case 4:
			return cpu_to_be32(data & 0xffffffff);
		default:
			return cpu_to_be64(data);
		}
	} else {
		switch (len) {
		case 1:
			return data & 0xff;
		case 2:
			return cpu_to_le16(data & 0xffff);
		case 4:
			return cpu_to_le32(data & 0xffffffff);
		default:
			return cpu_to_le64(data);
		}
	}

	return data;		/* Leave LE untouched */
}

static __always_inline void kvm_incr_pc(struct kvm_vcpu *vcpu)
{
	WARN_ON(vcpu_get_flag(vcpu, PENDING_EXCEPTION));
	vcpu_set_flag(vcpu, INCREMENT_PC);
}

#define kvm_pend_exception(v, e)					\
	do {								\
		WARN_ON(vcpu_get_flag((v), INCREMENT_PC));		\
		vcpu_set_flag((v), PENDING_EXCEPTION);			\
		vcpu_set_flag((v), e);					\
	} while (0)

#endif /* KVM_ARM64_KVM_EMULATE_H */
