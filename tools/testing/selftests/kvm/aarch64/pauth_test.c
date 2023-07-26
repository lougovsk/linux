// SPDX-License-Identifier: GPL-2.0-only
/*
 * pauth_test - Test for KVM guest pointer authentication.
 *
 * Copyright (c) 2023 Google LLC.
 *
 */

#define _GNU_SOURCE

#include <sched.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

enum uc_args {
	WAIT_MIGRATION,
	PASS,
	FAIL,
	FAIL_KVM,
	FAIL_INSTR,
};

static noinline void pac_corruptor(void)
{
	__asm__ __volatile__(
		"paciasp\n"
		"eor lr, lr, #1 << 53\n"
	);

	/* Migrate guest to another physical CPU before authentication */
	GUEST_SYNC(WAIT_MIGRATION);
	__asm__ __volatile__("autiasp\n");
}

static void guest_code(void)
{
	uint64_t sctlr = read_sysreg(sctlr_el1);

	/* Enable PAuth */
	sctlr |= SCTLR_ELx_ENIA | SCTLR_ELx_ENIB | SCTLR_ELx_ENDA | SCTLR_ELx_ENDB;
	write_sysreg(sctlr, sctlr_el1);
	isb();

	pac_corruptor();

	/* Shouldn't be here unless the pac_corruptor didn't do its work */
	GUEST_SYNC(FAIL);
	GUEST_DONE();
}

/* Guest will get an unknown exception if KVM doesn't support guest PAuth */
static void guest_unknown_handler(struct ex_regs *regs)
{
	GUEST_SYNC(FAIL_KVM);
	GUEST_DONE();
}

/* Guest will get a FPAC exception if KVM support guest PAuth */
static void guest_fpac_handler(struct ex_regs *regs)
{
	GUEST_SYNC(PASS);
	GUEST_DONE();
}

/* Guest will get an instruction abort exception if the PAuth instructions have
 * no effect (or PAuth not enabled in guest), which would cause guest to fetch
 * an invalid instruction due to the corrupted LR.
 */
static void guest_iabt_handler(struct ex_regs *regs)
{
	GUEST_SYNC(FAIL_INSTR);
	GUEST_DONE();
}

int main(void)
{
	struct kvm_vcpu_init init;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	cpu_set_t cpu_mask;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_PTRAUTH_ADDRESS));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_PTRAUTH_GENERIC));

	vm = vm_create(1);

	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= ((1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS) |
			     (1 << KVM_ARM_VCPU_PTRAUTH_GENERIC));

	vcpu = aarch64_vcpu_add(vm, 0, &init, guest_code);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);

	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_EC_UNKNOWN, guest_unknown_handler);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_EC_FPAC, guest_fpac_handler);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_EC_IABT, guest_iabt_handler);

	while (1) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_SYNC:
			switch (uc.args[1]) {
			case PASS:
				/* KVM guest PAuth works! */
				break;
			case WAIT_MIGRATION:
				sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask);
				CPU_CLR(sched_getcpu(), &cpu_mask);
				sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
				break;
			case FAIL:
				TEST_FAIL("Guest corruptor code doesn't work!\n");
				break;
			case FAIL_KVM:
				TEST_FAIL("KVM doesn't support guest PAuth!\n");
				break;
			case FAIL_INSTR:
				TEST_FAIL("Guest PAuth instructions don't work!\n");
				break;
			}
			break;
		case UCALL_DONE:
			goto done;
		default:
			TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
		}
	}

done:
	kvm_vm_free(vm);
}
