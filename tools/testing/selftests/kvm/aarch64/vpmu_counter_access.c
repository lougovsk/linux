// SPDX-License-Identifier: GPL-2.0-only
/*
 * vpmu_counter_access - Test vPMU event counter access
 *
 * Copyright (c) 2022 Google LLC.
 *
 * This test checks if the guest can see the same number of the PMU event
 * counters (PMCR_EL0.N) that userspace sets.
 * This test runs only when KVM_CAP_ARM_PMU_V3 is supported on the host.
 */
#include <kvm_util.h>
#include <processor.h>
#include <test_util.h>
#include <vgic.h>
#include <asm/perf_event.h>
#include <linux/bitfield.h>

/* The max number of the PMU event counters (excluding the cycle counter) */
#define ARMV8_PMU_MAX_GENERAL_COUNTERS	(ARMV8_PMU_MAX_COUNTERS - 1)

/*
 * The guest is configured with PMUv3 with @expected_pmcr_n number of
 * event counters.
 * Check if @expected_pmcr_n is consistent with PMCR_EL0.N.
 */
static void guest_code(uint64_t expected_pmcr_n)
{
	uint64_t pmcr, pmcr_n;

	GUEST_ASSERT(expected_pmcr_n <= ARMV8_PMU_MAX_GENERAL_COUNTERS);

	pmcr = read_sysreg(pmcr_el0);
	pmcr_n = FIELD_GET(ARMV8_PMU_PMCR_N, pmcr);

	/* Make sure that PMCR_EL0.N indicates the value userspace set */
	GUEST_ASSERT_2(pmcr_n == expected_pmcr_n, pmcr_n, expected_pmcr_n);

	GUEST_DONE();
}

#define GICD_BASE_GPA	0x8000000ULL
#define GICR_BASE_GPA	0x80A0000ULL

/* Create a VM that has one vCPU with PMUv3 configured. */
static struct kvm_vm *create_vpmu_vm(void *guest_code, struct kvm_vcpu **vcpup,
				     int *gic_fd)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_init init;
	uint8_t pmuver;
	uint64_t dfr0, irq = 23;
	struct kvm_device_attr irq_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_IRQ,
		.addr = (uint64_t)&irq,
	};
	struct kvm_device_attr init_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_INIT,
	};

	vm = vm_create(1);

	/* Create vCPU with PMUv3 */
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= (1 << KVM_ARM_VCPU_PMU_V3);
	vcpu = aarch64_vcpu_add(vm, 0, &init, guest_code);
	*gic_fd = vgic_v3_setup(vm, 1, 64, GICD_BASE_GPA, GICR_BASE_GPA);

	/* Make sure that PMUv3 support is indicated in the ID register */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), &dfr0);
	pmuver = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMUVER), dfr0);
	TEST_ASSERT(pmuver != ID_AA64DFR0_PMUVER_IMP_DEF &&
		    pmuver >= ID_AA64DFR0_PMUVER_8_0,
		    "Unexpected PMUVER (0x%x) on the vCPU with PMUv3", pmuver);

	/* Initialize vPMU */
	vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &irq_attr);
	vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &init_attr);

	*vcpup = vcpu;
	return vm;
}

static void run_vcpu(struct kvm_vcpu *vcpu, uint64_t pmcr_n)
{
	struct ucall uc;

	vcpu_args_set(vcpu, 1, pmcr_n);
	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT_2(uc, "values:%#lx %#lx");
		break;
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unknown ucall %lu", uc.cmd);
		break;
	}
}

/*
 * Create a guest with one vCPU, set the PMCR_EL0.N for the vCPU to @pmcr_n,
 * and run the test.
 */
static void run_test(uint64_t pmcr_n)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int gic_fd;
	uint64_t sp, pmcr, pmcr_orig;
	struct kvm_vcpu_init init;

	pr_debug("Test with pmcr_n %lu\n", pmcr_n);
	vm = create_vpmu_vm(guest_code, &vcpu, &gic_fd);

	/* Save the initial sp to restore them later to run the guest again */
	vcpu_get_reg(vcpu, ARM64_CORE_REG(sp_el1), &sp);

	/* Update the PMCR_EL0.N with @pmcr_n */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr_orig);
	pmcr = pmcr_orig & ~ARMV8_PMU_PMCR_N;
	pmcr |= (pmcr_n << ARMV8_PMU_PMCR_N_SHIFT);
	vcpu_set_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), pmcr);

	run_vcpu(vcpu, pmcr_n);

	/*
	 * Reset and re-initialize the vCPU, and run the guest code again to
	 * check if PMCR_EL0.N is preserved.
	 */
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= (1 << KVM_ARM_VCPU_PMU_V3);
	aarch64_vcpu_setup(vcpu, &init);
	vcpu_set_reg(vcpu, ARM64_CORE_REG(sp_el1), sp);
	vcpu_set_reg(vcpu, ARM64_CORE_REG(regs.pc), (uint64_t)guest_code);

	run_vcpu(vcpu, pmcr_n);

	close(gic_fd);
	kvm_vm_free(vm);
}

/*
 * Create a guest with one vCPU, and attempt to set the PMCR_EL0.N for
 * the vCPU to @pmcr_n, which is larger than the host value.
 * The attempt should fail as @pmcr_n is too big to set for the vCPU.
 */
static void run_error_test(uint64_t pmcr_n)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int gic_fd, ret;
	uint64_t pmcr, pmcr_orig;

	pr_debug("Error test with pmcr_n %lu (larger than the host)\n", pmcr_n);
	vm = create_vpmu_vm(guest_code, &vcpu, &gic_fd);

	/* Update the PMCR_EL0.N with @pmcr_n */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr_orig);
	pmcr = pmcr_orig & ~ARMV8_PMU_PMCR_N;
	pmcr |= (pmcr_n << ARMV8_PMU_PMCR_N_SHIFT);

	/* This should fail as @pmcr_n is too big to set for the vCPU */
	ret = __vcpu_set_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), pmcr);
	TEST_ASSERT(ret, "Setting PMCR to 0x%lx (orig PMCR 0x%lx) didn't fail",
		    pmcr, pmcr_orig);

	close(gic_fd);
	kvm_vm_free(vm);
}

/*
 * Return the default number of implemented PMU event counters excluding
 * the cycle counter (i.e. PMCR_EL0.N value) for the guest.
 */
static uint64_t get_pmcr_n_limit(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int gic_fd;
	uint64_t pmcr;

	vm = create_vpmu_vm(guest_code, &vcpu, &gic_fd);
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr);
	close(gic_fd);
	kvm_vm_free(vm);
	return FIELD_GET(ARMV8_PMU_PMCR_N, pmcr);
}

int main(void)
{
	uint64_t i, pmcr_n;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_PMU_V3));

	pmcr_n = get_pmcr_n_limit();
	for (i = 0; i <= pmcr_n; i++)
		run_test(i);

	for (i = pmcr_n + 1; i < ARMV8_PMU_MAX_COUNTERS; i++)
		run_error_test(i);

	return 0;
}
