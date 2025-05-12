// SPDX-License-Identifier: GPL-2.0-only
/*
 * The test validates both the virtual and physical timer IRQs using
 * CVAL and TVAL registers.
 *
 * Copyright (c) 2021, Google LLC.
 */
#include "arch_timer.h"
#include "delay.h"
#include "gic.h"
#include "processor.h"
#include "timer_test.h"
#include "ucall_common.h"
#include "vgic.h"
#include <nv_util.h>

enum guest_stage {
	GUEST_STAGE_VTIMER_CVAL = 1,
	GUEST_STAGE_VTIMER_TVAL,
	GUEST_STAGE_PTIMER_CVAL,
	GUEST_STAGE_PTIMER_TVAL,
	GUEST_STAGE_HVTIMER_CVAL,
	GUEST_STAGE_HVTIMER_TVAL,
	GUEST_STAGE_HPTIMER_CVAL,
	GUEST_STAGE_HPTIMER_TVAL,
	GUEST_STAGE_MAX,
};

static int vtimer_irq, ptimer_irq;
static int hvtimer_irq, hptimer_irq;

static void
guest_configure_timer_action(struct test_vcpu_shared_data *shared_data)
{
	switch (shared_data->guest_stage) {
	case GUEST_STAGE_VTIMER_CVAL:
		timer_set_next_cval_ms(VIRTUAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(VIRTUAL);
		timer_set_ctl(VIRTUAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_VTIMER_TVAL:
		timer_set_next_tval_ms(VIRTUAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(VIRTUAL);
		timer_set_ctl(VIRTUAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_PTIMER_CVAL:
		timer_set_next_cval_ms(PHYSICAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(PHYSICAL);
		timer_set_ctl(PHYSICAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_PTIMER_TVAL:
		timer_set_next_tval_ms(PHYSICAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(PHYSICAL);
		timer_set_ctl(PHYSICAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_HVTIMER_CVAL:
		timer_set_next_cval_ms(HVIRTUAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(HVIRTUAL);
		timer_set_ctl(HVIRTUAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_HVTIMER_TVAL:
		timer_set_next_tval_ms(HVIRTUAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(HVIRTUAL);
		timer_set_ctl(HVIRTUAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_HPTIMER_CVAL:
		timer_set_next_cval_ms(HPHYSICAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(HPHYSICAL);
		timer_set_ctl(HPHYSICAL, CTL_ENABLE);
		break;
	case GUEST_STAGE_HPTIMER_TVAL:
		timer_set_next_tval_ms(HPHYSICAL, test_args.timer_period_ms);
		shared_data->xcnt = timer_get_cntct(HPHYSICAL);
		timer_set_ctl(HPHYSICAL, CTL_ENABLE);
		break;
	default:
		GUEST_ASSERT(0);
	}
}

static void guest_validate_irq(unsigned int intid,
				struct test_vcpu_shared_data *shared_data)
{
	enum guest_stage stage = shared_data->guest_stage;
	uint64_t xcnt = 0, xcnt_diff_us, cval = 0;
	unsigned long xctl = 0;
	unsigned int timer_irq = 0;
	unsigned int accessor;

	if (intid == IAR_SPURIOUS)
		return;

	switch (stage) {
	case GUEST_STAGE_VTIMER_CVAL:
	case GUEST_STAGE_VTIMER_TVAL:
		accessor = VIRTUAL;
		timer_irq = vtimer_irq;
		break;
	case GUEST_STAGE_PTIMER_CVAL:
	case GUEST_STAGE_PTIMER_TVAL:
		accessor = PHYSICAL;
		timer_irq = ptimer_irq;
		break;
	case GUEST_STAGE_HVTIMER_CVAL:
	case GUEST_STAGE_HVTIMER_TVAL:
		accessor = HVIRTUAL;
		timer_irq = hvtimer_irq;
		break;
	case GUEST_STAGE_HPTIMER_CVAL:
	case GUEST_STAGE_HPTIMER_TVAL:
		accessor = HPHYSICAL;
		timer_irq = hptimer_irq;
		break;
	default:
		GUEST_ASSERT(0);
		return;
	}

	xctl = timer_get_ctl(accessor);
	if ((xctl & CTL_IMASK) || !(xctl & CTL_ENABLE))
		return;

	timer_set_ctl(accessor, CTL_IMASK);
	xcnt = timer_get_cntct(accessor);
	cval = timer_get_cval(accessor);

	xcnt_diff_us = cycles_to_usec(xcnt - shared_data->xcnt);

	/* Make sure we are dealing with the correct timer IRQ */
	GUEST_ASSERT_EQ(intid, timer_irq);

	/* Basic 'timer condition met' check */
	__GUEST_ASSERT(xcnt >= cval,
		       "xcnt = 0x%lx, cval = 0x%lx, xcnt_diff_us = 0x%lx",
		       xcnt, cval, xcnt_diff_us);
	__GUEST_ASSERT(xctl & CTL_ISTATUS, "xctl = 0x%lx", xctl);

	WRITE_ONCE(shared_data->nr_iter, shared_data->nr_iter + 1);
}

static void guest_irq_handler(struct ex_regs *regs)
{
	unsigned int intid = gic_get_and_ack_irq();
	uint32_t cpu = guest_get_vcpuid();
	struct test_vcpu_shared_data *shared_data = &vcpu_shared_data[cpu];

	guest_validate_irq(intid, shared_data);

	gic_set_eoi(intid);
}

static void guest_run_stage(struct test_vcpu_shared_data *shared_data,
				enum guest_stage stage)
{
	uint32_t irq_iter, config_iter;

	shared_data->guest_stage = stage;
	shared_data->nr_iter = 0;

	for (config_iter = 0; config_iter < test_args.nr_iter; config_iter++) {
		/* Setup the next interrupt */
		guest_configure_timer_action(shared_data);

		/* Setup a timeout for the interrupt to arrive */
		udelay(msecs_to_usecs(test_args.timer_period_ms) +
			test_args.timer_err_margin_us);

		irq_iter = READ_ONCE(shared_data->nr_iter);
		__GUEST_ASSERT(config_iter + 1 == irq_iter,
				"config_iter + 1 = 0x%x, irq_iter = 0x%x.\n"
				"  Guest timer interrupt was not triggered within the specified\n"
				"  interval, try to increase the error margin by [-e] option.\n",
				config_iter + 1, irq_iter);
	}
}

static void guest_code(void)
{
	uint32_t cpu = guest_get_vcpuid();
	struct test_vcpu_shared_data *shared_data = &vcpu_shared_data[cpu];
	bool is_nested = false;
	enum arch_timer vtimer, ptimer;
	int vtmr_irq, ptmr_irq;
	enum guest_stage stage_vtimer_cval, stage_vtimer_tval;
	enum guest_stage stage_ptimer_cval, stage_ptimer_tval;

	if (read_sysreg(CurrentEL) == CurrentEL_EL2)
		is_nested = true;

	local_irq_disable();
	gic_init(GIC_V3, test_args.nr_vcpus);

	if (is_nested) {

		vtimer = HVIRTUAL;
		ptimer = HPHYSICAL;
		vtmr_irq = hvtimer_irq;
		ptmr_irq = hptimer_irq;
		stage_vtimer_cval = GUEST_STAGE_HVTIMER_CVAL;
		stage_vtimer_tval = GUEST_STAGE_HVTIMER_TVAL;
		stage_ptimer_cval = GUEST_STAGE_HPTIMER_CVAL;
		stage_ptimer_tval = GUEST_STAGE_HPTIMER_TVAL;
	} else {
		vtimer = VIRTUAL;
		ptimer = PHYSICAL;
		vtmr_irq = vtimer_irq;
		ptmr_irq = ptimer_irq;
		stage_vtimer_cval = GUEST_STAGE_VTIMER_CVAL;
		stage_vtimer_tval = GUEST_STAGE_VTIMER_TVAL;
		stage_ptimer_cval = GUEST_STAGE_PTIMER_CVAL;
		stage_ptimer_tval = GUEST_STAGE_PTIMER_TVAL;
	}

	timer_set_ctl(vtimer, CTL_IMASK);
	timer_set_ctl(ptimer, CTL_IMASK);
	gic_irq_enable(vtmr_irq);
	gic_irq_enable(ptmr_irq);

	local_irq_enable();

	guest_run_stage(shared_data, stage_vtimer_cval);
	guest_run_stage(shared_data, stage_vtimer_tval);
	guest_run_stage(shared_data, stage_ptimer_cval);
	guest_run_stage(shared_data, stage_ptimer_tval);

	GUEST_DONE();
}

static void test_init_timer_irq(struct kvm_vm *vm)
{

	/* Timer initid should be same for all the vCPUs, so query only vCPU-0 */
	if (is_vcpu_nested(vcpus[0])) {
		vcpu_device_attr_get(vcpus[0], KVM_ARM_VCPU_TIMER_CTRL,
				KVM_ARM_VCPU_TIMER_IRQ_HPTIMER, &hptimer_irq);
		vcpu_device_attr_get(vcpus[0], KVM_ARM_VCPU_TIMER_CTRL,
				KVM_ARM_VCPU_TIMER_IRQ_HVTIMER, &hvtimer_irq);

		sync_global_to_guest(vm, hptimer_irq);
		sync_global_to_guest(vm, hvtimer_irq);

		pr_debug("hptimer_irq: %d; hvtimer_irq: %d\n", hptimer_irq, hvtimer_irq);
	} else {
		vcpu_device_attr_get(vcpus[0], KVM_ARM_VCPU_TIMER_CTRL,
				KVM_ARM_VCPU_TIMER_IRQ_PTIMER, &ptimer_irq);
		vcpu_device_attr_get(vcpus[0], KVM_ARM_VCPU_TIMER_CTRL,
				KVM_ARM_VCPU_TIMER_IRQ_VTIMER, &vtimer_irq);

		sync_global_to_guest(vm, ptimer_irq);
		sync_global_to_guest(vm, vtimer_irq);

		pr_debug("ptimer_irq: %d; vtimer_irq: %d\n", ptimer_irq, vtimer_irq);
	}
}

static int gic_fd;

struct kvm_vm *test_vm_create(void)
{
	struct kvm_vm *vm;
	unsigned int i;
	int nr_vcpus = test_args.nr_vcpus;

	if (test_args.is_nested)
		vm = nv_vm_create_with_vcpus_gic(nr_vcpus, vcpus, NULL, guest_code);
	else
		vm = vm_create_with_vcpus(nr_vcpus, guest_code, vcpus);

	vm_init_descriptor_tables(vm);
	vm_install_exception_handler(vm, VECTOR_IRQ_CURRENT, guest_irq_handler);

	if (!test_args.reserved) {
		if (kvm_has_cap(KVM_CAP_COUNTER_OFFSET)) {
			struct kvm_arm_counter_offset offset = {
				.counter_offset = test_args.counter_offset,
				.reserved = 0,
			};
			vm_ioctl(vm, KVM_ARM_SET_COUNTER_OFFSET, &offset);
		} else
			TEST_FAIL("no support for global offset");
	}

	for (i = 0; i < nr_vcpus; i++)
		vcpu_init_descriptor_tables(vcpus[i]);

	test_init_timer_irq(vm);
	gic_fd = vgic_v3_setup(vm, nr_vcpus, 64);
	__TEST_REQUIRE(gic_fd >= 0, "Failed to create vgic-v3");

	/* Make all the test's cmdline args visible to the guest */
	sync_global_to_guest(vm, test_args);

	return vm;
}

void test_vm_cleanup(struct kvm_vm *vm)
{
	close(gic_fd);
	kvm_vm_free(vm);
}
