/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __KVM_ARM64_KVM_HOST_H
#define __KVM_ARM64_KVM_HOST_H

#include <linux/types.h>

#define KVM_VCPU_MAX_FEATURES 9

#define KVM_REQ_SLEEP \
	KVM_ARCH_REQ_FLAGS(0, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_IRQ_PENDING		KVM_ARCH_REQ(1)
#define KVM_REQ_VCPU_RESET		KVM_ARCH_REQ(2)
#define KVM_REQ_RECORD_STEAL		KVM_ARCH_REQ(3)
#define KVM_REQ_RELOAD_GICv4		KVM_ARCH_REQ(4)
#define KVM_REQ_RELOAD_PMU		KVM_ARCH_REQ(5)
#define KVM_REQ_SUSPEND			KVM_ARCH_REQ(6)
#define KVM_REQ_RESYNC_PMU_EL0		KVM_ARCH_REQ(7)
#define KVM_REQ_NESTED_S2_UNMAP		KVM_ARCH_REQ(8)
#define KVM_REQ_GUEST_HYP_IRQ_PENDING	KVM_ARCH_REQ(9)
#define KVM_REQ_MAP_L1_VNCR_EL2		KVM_ARCH_REQ(10)
#define KVM_REQ_VGIC_PROCESS_UPDATE	KVM_ARCH_REQ(11)

struct vcpu_reset_state {
	unsigned long	pc;
	unsigned long	r0;
	bool		be;
	bool		reset;
};

/* MMIO helpers */
void kvm_mmio_write_buf(void *buf, unsigned int len, unsigned long data);
unsigned long kvm_mmio_read_buf(const void *buf, unsigned int len);

int kvm_handle_mmio_return(struct kvm_vcpu *vcpu);
int io_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa);

/* Exception pending */
#define PENDING_EXCEPTION	__vcpu_single_flag(iflags, BIT(0))
/*
 * PC increment. Overlaps with EXCEPT_MASK on purpose so that it can't
 * be set together with an exception...
 */
#define INCREMENT_PC		__vcpu_single_flag(iflags, BIT(1))
/* Target EL/MODE (not a single flag, but let's abuse the macro) */
#define EXCEPT_MASK		__vcpu_single_flag(iflags, GENMASK(3, 1))

/* Helpers to encode exceptions with minimum fuss */
#define __EXCEPT_MASK_VAL	unpack_vcpu_flag(EXCEPT_MASK)
#define __EXCEPT_SHIFT		__builtin_ctzl(__EXCEPT_MASK_VAL)
#define __vcpu_except_flags(_f)	iflags, (_f << __EXCEPT_SHIFT), __EXCEPT_MASK_VAL

/*
 * When PENDING_EXCEPTION is set, EXCEPT_MASK can take the following
 * values:
 *
 * For AArch32 EL1:
 */
#define EXCEPT_AA32_UND		__vcpu_except_flags(0)
#define EXCEPT_AA32_IABT	__vcpu_except_flags(1)
#define EXCEPT_AA32_DABT	__vcpu_except_flags(2)
/* For AArch64: */
#define EXCEPT_AA64_EL1_SYNC	__vcpu_except_flags(0)
#define EXCEPT_AA64_EL1_IRQ	__vcpu_except_flags(1)
#define EXCEPT_AA64_EL1_FIQ	__vcpu_except_flags(2)
#define EXCEPT_AA64_EL1_SERR	__vcpu_except_flags(3)
/* For AArch64 with NV: */
#define EXCEPT_AA64_EL2_SYNC	__vcpu_except_flags(4)
#define EXCEPT_AA64_EL2_IRQ	__vcpu_except_flags(5)
#define EXCEPT_AA64_EL2_FIQ	__vcpu_except_flags(6)
#define EXCEPT_AA64_EL2_SERR	__vcpu_except_flags(7)

static inline bool kvm_supports_32bit_el0(void)
{
	return false;
}

#define vcpu_is_protected(vcpu)		kvm_vm_is_protected((vcpu)->kvm)

/*
 * If we encounter a data abort without valid instruction syndrome
 * information, report this to user space.  User space can (and
 * should) opt in to this feature if KVM_CAP_ARM_NISV_TO_USER is
 * supported.
 */
#define KVM_ARCH_FLAG_RETURN_NISV_IO_ABORT_TO_USER	0
/* Memory Tagging Extension enabled for the guest */
#define KVM_ARCH_FLAG_MTE_ENABLED			1
/* At least one vCPU has ran in the VM */
#define KVM_ARCH_FLAG_HAS_RAN_ONCE			2
/* The vCPU feature set for the VM is configured */
#define KVM_ARCH_FLAG_VCPU_FEATURES_CONFIGURED		3
/* PSCI SYSTEM_SUSPEND enabled for the guest */
#define KVM_ARCH_FLAG_SYSTEM_SUSPEND_ENABLED		4
/* VM counter offset */
#define KVM_ARCH_FLAG_VM_COUNTER_OFFSET			5
/* Timer PPIs made immutable */
#define KVM_ARCH_FLAG_TIMER_PPIS_IMMUTABLE		6
/* Initial ID reg values loaded */
#define KVM_ARCH_FLAG_ID_REGS_INITIALIZED		7
/* Fine-Grained UNDEF initialised */
#define KVM_ARCH_FLAG_FGU_INITIALIZED			8
/* SVE exposed to guest */
#define KVM_ARCH_FLAG_GUEST_HAS_SVE			9
/* MIDR_EL1, REVIDR_EL1, and AIDR_EL1 are writable from userspace */
#define KVM_ARCH_FLAG_WRITABLE_IMP_ID_REGS		10
/* Unhandled SEAs are taken to userspace */
#define KVM_ARCH_FLAG_EXIT_SEA				11

/* Implemented in architecture specific code */
unsigned long system_supported_vcpu_features(void);

#endif /* __KVM_ARM64_KVM_HOST_H */
