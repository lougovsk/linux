// SPDX-License-Identifier: GPL-2.0
/*
 * pmu_event_filter_test - Test user limit pmu event for guest.
 *
 * Copyright (c) 2023 Red Hat, Inc.
 *
 * This test checks if the guest only see the limited pmu event that userspace
 * sets, if the guest can use those events which user allow, and if the guest
 * can't use those events which user deny.
 * It also checks that setting invalid filter ranges return the expected error.
 * This test runs only when KVM_CAP_ARM_PMU_V3, KVM_ARM_VCPU_PMU_V3_FILTER
 * is supported on the host.
 */
#include <kvm_util.h>
#include <processor.h>
#include <vgic.h>
#include <vpmu.h>
#include <test_util.h>
#include <perf/arm_pmuv3.h>

struct pmce{
	uint64_t pmceid0;
	uint64_t pmceid1;
} supported_pmce, guest_pmce;

static struct vpmu_vm *vpmu_vm;

#define FILTER_NR 10

struct test_desc {
	const char *name;
	struct kvm_pmu_event_filter filter[FILTER_NR];
};

#define __DEFINE_FILTER(base, num, act)		\
	((struct kvm_pmu_event_filter) {	\
		.base_event	= base,		\
		.nevents	= num,		\
		.action		= act,		\
	})

#define DEFINE_FILTER(base, act) __DEFINE_FILTER(base, 1, act)

#define EMPTY_FILTER	{ 0 }

#define SW_INCR		0x0
#define INST_RETIRED	0x8
#define BR_RETIRED	0x21

static void guest_code(void)
{
	uint64_t pmceid0 = read_sysreg(pmceid0_el0);
	uint64_t pmceid1 = read_sysreg(pmceid1_el0);

	GUEST_ASSERT_EQ(guest_pmce.pmceid0, pmceid0);
	GUEST_ASSERT_EQ(guest_pmce.pmceid1, pmceid1);

	GUEST_DONE();
}

static void guest_get_pmceid(void)
{
	supported_pmce.pmceid0 = read_sysreg(pmceid0_el0);
	supported_pmce.pmceid1 = read_sysreg(pmceid1_el0);

	GUEST_DONE();
}

static void pmu_event_filter_init(struct vpmu_vm *vm, void *arg)
{
	struct kvm_device_attr attr = {
		.group	= KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr	= KVM_ARM_VCPU_PMU_V3_FILTER,
	};
	struct kvm_pmu_event_filter *filter = (struct kvm_pmu_event_filter *)arg;

	while (filter && filter->nevents != 0) {
		attr.addr = (uint64_t)filter;
		vcpu_ioctl(vm->vcpu, KVM_SET_DEVICE_ATTR, &attr);
		filter++;
	}
}

static void create_vpmu_vm_with_filter(void *guest_code,
				       struct kvm_pmu_event_filter *filter)
{
	vpmu_vm = __create_vpmu_vm(guest_code, pmu_event_filter_init, filter);
}

static void run_vcpu(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	while (1) {
		vcpu_run(vcpu);
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			return;
		default:
			TEST_FAIL("Unknown ucall %lu", uc.cmd);
		}
	}
}

static void set_pmce(struct pmce *pmce, int action, int event)
{
	int base = 0;
	uint64_t *pmceid = NULL;

	if (event >= 0x4000) {
		event -= 0x4000;
		base = 32;
	}

	if (event >= 0 && event <= 0x1F) {
		pmceid = &pmce->pmceid0;
	} else if (event >= 0x20 && event <= 0x3F) {
		event -= 0x20;
		pmceid = &pmce->pmceid1;
	} else {
		return;
	}

	event += base;
	if (action == KVM_PMU_EVENT_ALLOW)
		*pmceid |= BIT(event);
	else
		*pmceid &= ~BIT(event);
}

static void prepare_guest_pmce(struct kvm_pmu_event_filter *filter)
{
	struct pmce pmce_mask = { ~0, ~0 };
	bool first_filter = true;

	while (filter && filter->nevents != 0) {
		if (first_filter) {
			if (filter->action == KVM_PMU_EVENT_ALLOW)
				memset(&pmce_mask, 0, sizeof(pmce_mask));
			first_filter = false;
		}

		set_pmce(&pmce_mask, filter->action, filter->base_event);
		filter++;
	}

	guest_pmce.pmceid0 = supported_pmce.pmceid0 & pmce_mask.pmceid0;
	guest_pmce.pmceid1 = supported_pmce.pmceid1 & pmce_mask.pmceid1;
}

static void run_test(struct test_desc *t)
{
	pr_debug("Test: %s\n", t->name);

	create_vpmu_vm_with_filter(guest_code, t->filter);
	prepare_guest_pmce(t->filter);
	sync_global_to_guest(vpmu_vm->vm, guest_pmce);

	run_vcpu(vpmu_vm->vcpu);

	destroy_vpmu_vm(vpmu_vm);
}

static struct test_desc tests[] = {
	{"without_filter", { EMPTY_FILTER }},
	{"member_allow_filter",
	 {DEFINE_FILTER(SW_INCR, 0), DEFINE_FILTER(INST_RETIRED, 0),
	  DEFINE_FILTER(BR_RETIRED, 0), EMPTY_FILTER}},
	{"member_deny_filter",
	 {DEFINE_FILTER(SW_INCR, 1), DEFINE_FILTER(INST_RETIRED, 1),
	  DEFINE_FILTER(BR_RETIRED, 1), EMPTY_FILTER}},
	{"not_member_deny_filter",
	 {DEFINE_FILTER(SW_INCR, 1), EMPTY_FILTER}},
	{"not_member_allow_filter",
	 {DEFINE_FILTER(SW_INCR, 0), EMPTY_FILTER}},
	{ 0 }
};

static void for_each_test(void)
{
	struct test_desc *t;

	for (t = &tests[0]; t->name; t++)
		run_test(t);
}

static void set_invalid_filter(struct vpmu_vm *vm, void *arg)
{
	struct kvm_pmu_event_filter invalid;
	struct kvm_device_attr attr = {
		.group	= KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr	= KVM_ARM_VCPU_PMU_V3_FILTER,
		.addr	= (uint64_t)&invalid,
	};
	int ret = 0;

	/* The max event number is (1 << 16), set a range largeer than it. */
	invalid = __DEFINE_FILTER(BIT(15), BIT(15)+1, 0);
	ret = __vcpu_ioctl(vm->vcpu, KVM_SET_DEVICE_ATTR, &attr);
	TEST_ASSERT(ret && errno == EINVAL, "Set Invalid filter range "
		    "ret = %d, errno = %d (expected ret = -1, errno = EINVAL)",
		    ret, errno);

	ret = 0;

	/* Set the Invalid action. */
	invalid = __DEFINE_FILTER(0, 1, 3);
	ret = __vcpu_ioctl(vm->vcpu, KVM_SET_DEVICE_ATTR, &attr);
	TEST_ASSERT(ret && errno == EINVAL, "Set Invalid filter action "
		    "ret = %d, errno = %d (expected ret = -1, errno = EINVAL)",
		    ret, errno);
}

static void test_invalid_filter(void)
{
	vpmu_vm = __create_vpmu_vm(guest_code, set_invalid_filter, NULL);
	destroy_vpmu_vm(vpmu_vm);
}

static bool kvm_supports_pmu_event_filter(void)
{
	int r;

	vpmu_vm = create_vpmu_vm(guest_code);

	r = __kvm_has_device_attr(vpmu_vm->vcpu->fd, KVM_ARM_VCPU_PMU_V3_CTRL,
				  KVM_ARM_VCPU_PMU_V3_FILTER);

	destroy_vpmu_vm(vpmu_vm);
	return !r;
}

static bool host_pmu_supports_events(void)
{
	vpmu_vm = create_vpmu_vm(guest_get_pmceid);

	memset(&supported_pmce, 0, sizeof(supported_pmce));
	sync_global_to_guest(vpmu_vm->vm, supported_pmce);
	run_vcpu(vpmu_vm->vcpu);
	sync_global_from_guest(vpmu_vm->vm, supported_pmce);
	destroy_vpmu_vm(vpmu_vm);

	return supported_pmce.pmceid0 & (BR_RETIRED | INST_RETIRED);
}

int main(void)
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_PMU_V3));
	TEST_REQUIRE(kvm_supports_pmu_event_filter());
	TEST_REQUIRE(host_pmu_supports_events());

	for_each_test();

	test_invalid_filter();
}
