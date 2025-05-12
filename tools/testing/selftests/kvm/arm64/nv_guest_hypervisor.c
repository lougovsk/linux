// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Ampere Computing LLC
 */
#include <kvm_util.h>
#include <nv_util.h>
#include <processor.h>

static void guest_code(void)
{
	if (read_sysreg(CurrentEL) == CurrentEL_EL2)
		GUEST_PRINTF("Test PASS\n");
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
	int gic_fd = -1;

	vm = nv_vm_create_with_vcpus_gic(1, &vcpu, &gic_fd, guest_code);
	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_UNKNOWN, guest_undef_handler);

	test_run_vcpu(vcpu);

	vgic_v3_close(gic_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	test_nv_guest_hypervisor();
	return 0;
}
