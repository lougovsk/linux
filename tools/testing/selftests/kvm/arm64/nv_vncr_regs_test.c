// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Ampere Computing LLC
 *
 * This is a test to validate Nested Virtualization.
 */
#include <kvm_util.h>
#include <nv_util.h>
#include <processor.h>
#include <vgic.h>

#define __check_sr_read(r)					\
	({							\
		uint64_t val;					\
								\
		handled = false;				\
		dsb(sy);					\
		val = read_sysreg_s(SYS_ ## r);			\
		val;						\
	})

#define __check_sr_write(r)					\
	do {							\
		handled = false;				\
		dsb(sy);					\
		write_sysreg_s(0, SYS_ ## r);			\
		isb();						\
	} while (0)


#define check_sr_read(r)					  \
	do {							  \
		__check_sr_read(r);				  \
		__GUEST_ASSERT(!handled, #r "Read Test Failed");  \
	} while (0)

#define check_sr_write(r)					  \
	do {							  \
		__check_sr_write(r);				  \
		__GUEST_ASSERT(!handled, #r "Write Test Failed"); \
	} while (0)

#define check_sr_rw(r)				\
	do {					\
		GUEST_PRINTF("%s\n", #r);	\
		check_sr_write(r);		\
		check_sr_read(r);		\
	} while (0)

static void test_vncr_mapped_regs(void);
static void regs_test_ich_lr(void);

static volatile bool handled;

static void regs_test_ich_lr(void)
{
	int nr_lr, lr;

	nr_lr  = (read_sysreg_s(SYS_ICH_VTR_EL2) & 0xf);

	for (lr = 0; lr <= nr_lr;  lr++) {
		switch (lr) {
		case 0:
			check_sr_rw(ICH_LR0_EL2);
			break;
		case 1:
			check_sr_rw(ICH_LR1_EL2);
			break;
		case 2:
			check_sr_rw(ICH_LR2_EL2);
			break;
		case 3:
			check_sr_rw(ICH_LR3_EL2);
			break;
		case 4:
			check_sr_rw(ICH_LR4_EL2);
			break;
		case 5:
			check_sr_rw(ICH_LR5_EL2);
			break;
		case 6:
			check_sr_rw(ICH_LR6_EL2);
			break;
		case 7:
			check_sr_rw(ICH_LR7_EL2);
			break;
		case 8:
			check_sr_rw(ICH_LR8_EL2);
			break;
		case 9:
			check_sr_rw(ICH_LR9_EL2);
			break;
		case 10:
			check_sr_rw(ICH_LR10_EL2);
			break;
		case 11:
			check_sr_rw(ICH_LR11_EL2);
			break;
		case 12:
			check_sr_rw(ICH_LR12_EL2);
			break;
		case 13:
			check_sr_rw(ICH_LR13_EL2);
			break;
		case 14:
			check_sr_rw(ICH_LR14_EL2);
			break;
		case 15:
			check_sr_rw(ICH_LR15_EL2);
			break;
		default:
			break;
		}
	}
}

/*
 * Validate READ/WRITE to VNCR Mapped registers for NV1=0
 */

static void test_vncr_mapped_regs(void)
{
	/*
	 * Access all VNCR Mapped registers, and fail if we get an UNDEF.
	 */

	GUEST_PRINTF("VNCR Mapped registers access test:\n");
	check_sr_rw(VTTBR_EL2);
	check_sr_rw(VTCR_EL2);
	check_sr_rw(VMPIDR_EL2);
	check_sr_rw(CNTVOFF_EL2);
	check_sr_rw(HCR_EL2);
	check_sr_rw(HSTR_EL2);
	check_sr_rw(VPIDR_EL2);
	check_sr_rw(TPIDR_EL2);
	check_sr_rw(VNCR_EL2);
	check_sr_rw(CPACR_EL12);
	check_sr_rw(CONTEXTIDR_EL12);
	check_sr_rw(SCTLR_EL12);
	check_sr_rw(ACTLR_EL1);
	check_sr_rw(TCR_EL12);
	check_sr_rw(AFSR0_EL12);
	check_sr_rw(AFSR1_EL12);
	check_sr_rw(ESR_EL12);
	check_sr_rw(MAIR_EL12);
	check_sr_rw(AMAIR_EL12);
	check_sr_rw(MDSCR_EL1);
	check_sr_rw(SPSR_EL12);
	check_sr_rw(CNTV_CVAL_EL02);
	check_sr_rw(CNTV_CTL_EL02);
	check_sr_rw(CNTP_CVAL_EL02);
	check_sr_rw(CNTP_CTL_EL02);
	check_sr_rw(HAFGRTR_EL2);
	check_sr_rw(TTBR0_EL12);
	check_sr_rw(TTBR1_EL12);
	check_sr_rw(FAR_EL12);
	check_sr_rw(ELR_EL12);
	check_sr_rw(SP_EL1);
	check_sr_rw(VBAR_EL12);

	regs_test_ich_lr();

	check_sr_rw(ICH_AP0R0_EL2);
	check_sr_rw(ICH_AP1R0_EL2);
	check_sr_rw(ICH_HCR_EL2);
	check_sr_rw(ICH_VMCR_EL2);
	check_sr_rw(VDISR_EL2);
	check_sr_rw(MPAM1_EL12);
	check_sr_rw(MPAMHCR_EL2);
	check_sr_rw(MPAMVPMV_EL2);
	check_sr_rw(MPAMVPM0_EL2);
	check_sr_rw(MPAMVPM1_EL2);
	check_sr_rw(MPAMVPM2_EL2);
	check_sr_rw(MPAMVPM3_EL2);
	check_sr_rw(MPAMVPM4_EL2);
	check_sr_rw(MPAMVPM5_EL2);
	check_sr_rw(MPAMVPM6_EL2);
	check_sr_rw(MPAMVPM7_EL2);
}

static void guest_code(void)
{
	if (read_sysreg(CurrentEL) != CurrentEL_EL2)
		GUEST_FAIL("Fail to run in vEL2\n");

	test_vncr_mapped_regs();
	GUEST_DONE();
}

static void guest_undef_handler(struct ex_regs *regs)
{
	handled = true;
	regs->pc += 4;
	GUEST_FAIL("TEST FAIL: register access trap to EL2");
}

static void test_run_vcpu(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	do {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_PRINTF:
			printf("%s", uc.buffer);
			break;
		case UCALL_DONE:
			printf("TEST PASS\n");
			break;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	} while (uc.cmd != UCALL_DONE);
}

static void test_nv_vncr(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct kvm_vcpu_init init;
	int gic_fd;

	vm = vm_create(1);
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);

	init.features[0] = 0;
	init_vcpu_nested(&init);
	vcpu = aarch64_vcpu_add(vm, 0, &init, guest_code);

	__TEST_REQUIRE(is_vcpu_nested(vcpu), "Failed to Enable NV");

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	gic_fd = vgic_v3_setup(vm, 1, 64);
	__TEST_REQUIRE(gic_fd >= 0, "Failed to create vgic-v3");

	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_UNKNOWN, guest_undef_handler);

	test_run_vcpu(vcpu);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_EL2));

	test_nv_vncr();

	return 0;
}
