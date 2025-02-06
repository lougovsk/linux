// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Ampere Computing LLC
 */
#include <kvm_util.h>
#include <nv_util.h>
#include <processor.h>
#include <vgic.h>

static void guest_code(void)
{
	if (read_sysreg(CurrentEL) == CurrentEL_EL2)
		GUEST_PRINTF("Executing guest code in vEL2\n");
	else
		GUEST_FAIL("Fail to run in vEL2\n");

	GUEST_DONE();
}

static void guest_undef_handler(struct ex_regs *regs)
{
	GUEST_FAIL("Unexpected exception far_el1 = 0x%lx", read_sysreg(far_el1));
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
			printf("Test PASS\n");
			break;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	} while (uc.cmd != UCALL_DONE);
}

static void test_nv_guest_hypervisor(void)
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

	test_nv_guest_hypervisor();

	return 0;
}
