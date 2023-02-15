// SPDX-License-Identifier: GPL-2.0-only
/*
 * vpmu_test - Test the vPMU
 *
 * The test suit contains a series of checks to validate the vPMU
 * functionality. This test runs only when KVM_CAP_ARM_PMU_V3 is
 * supported on the host. The tests include:
 *
 * 1. Check if the guest can see the same number of the PMU event
 * counters (PMCR_EL0.N) that userspace sets, if the guest can access
 * those counters, and if the guest cannot access any other counters.
 *
 * 2. Test the functionality of KVM's KVM_ARM_VCPU_PMU_V3_FILTER
 * attribute by applying a series of filters in various combinations
 * of allowing or denying the events. The guest validates it by
 * checking if it's able to count only the events that are allowed.
 *
 * 3. KVM doesn't allow the guest to count the events attributed with
 * higher exception levels (EL2, EL3). Verify this functionality by
 * configuring and trying to count the events for EL2 in the guest.
 *
 * 4. Since the PMU registers are per-cpu, stress KVM by frequently
 * migrating the guest vCPU to random pCPUs in the system, and check
 * if the vPMU is still behaving as expected.
 *
 * Copyright (c) 2022 Google LLC.
 *
 */
#define _GNU_SOURCE

#include <kvm_util.h>
#include <processor.h>
#include <test_util.h>
#include <vgic.h>
#include <asm/perf_event.h>
#include <linux/arm-smccc.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/sysinfo.h>

#include "delay.h"

/* The max number of the PMU event counters (excluding the cycle counter) */
#define ARMV8_PMU_MAX_GENERAL_COUNTERS	(ARMV8_PMU_MAX_COUNTERS - 1)

/* The max number of event numbers that's supported */
#define ARMV8_PMU_MAX_EVENTS		64

#define msecs_to_usecs(msec)		((msec) * 1000LL)

/*
 * The macros and functions below for reading/writing PMEV{CNTR,TYPER}<n>_EL0
 * were basically copied from arch/arm64/kernel/perf_event.c.
 */
#define PMEVN_CASE(n, case_macro) \
	case n: case_macro(n); break

#define PMEVN_SWITCH(x, case_macro)				\
	do {							\
		switch (x) {					\
		PMEVN_CASE(0,  case_macro);			\
		PMEVN_CASE(1,  case_macro);			\
		PMEVN_CASE(2,  case_macro);			\
		PMEVN_CASE(3,  case_macro);			\
		PMEVN_CASE(4,  case_macro);			\
		PMEVN_CASE(5,  case_macro);			\
		PMEVN_CASE(6,  case_macro);			\
		PMEVN_CASE(7,  case_macro);			\
		PMEVN_CASE(8,  case_macro);			\
		PMEVN_CASE(9,  case_macro);			\
		PMEVN_CASE(10, case_macro);			\
		PMEVN_CASE(11, case_macro);			\
		PMEVN_CASE(12, case_macro);			\
		PMEVN_CASE(13, case_macro);			\
		PMEVN_CASE(14, case_macro);			\
		PMEVN_CASE(15, case_macro);			\
		PMEVN_CASE(16, case_macro);			\
		PMEVN_CASE(17, case_macro);			\
		PMEVN_CASE(18, case_macro);			\
		PMEVN_CASE(19, case_macro);			\
		PMEVN_CASE(20, case_macro);			\
		PMEVN_CASE(21, case_macro);			\
		PMEVN_CASE(22, case_macro);			\
		PMEVN_CASE(23, case_macro);			\
		PMEVN_CASE(24, case_macro);			\
		PMEVN_CASE(25, case_macro);			\
		PMEVN_CASE(26, case_macro);			\
		PMEVN_CASE(27, case_macro);			\
		PMEVN_CASE(28, case_macro);			\
		PMEVN_CASE(29, case_macro);			\
		PMEVN_CASE(30, case_macro);			\
		default:					\
			GUEST_ASSERT_1(0, x);			\
		}						\
	} while (0)

#define RETURN_READ_PMEVCNTRN(n) \
	return read_sysreg(pmevcntr##n##_el0)
static unsigned long read_pmevcntrn(int n)
{
	PMEVN_SWITCH(n, RETURN_READ_PMEVCNTRN);
	return 0;
}

#define WRITE_PMEVCNTRN(n) \
	write_sysreg(val, pmevcntr##n##_el0)
static void write_pmevcntrn(int n, unsigned long val)
{
	PMEVN_SWITCH(n, WRITE_PMEVCNTRN);
	isb();
}

#define READ_PMEVTYPERN(n) \
	return read_sysreg(pmevtyper##n##_el0)
static unsigned long read_pmevtypern(int n)
{
	PMEVN_SWITCH(n, READ_PMEVTYPERN);
	return 0;
}

#define WRITE_PMEVTYPERN(n) \
	write_sysreg(val, pmevtyper##n##_el0)
static void write_pmevtypern(int n, unsigned long val)
{
	PMEVN_SWITCH(n, WRITE_PMEVTYPERN);
	isb();
}

/* Read PMEVTCNTR<n>_EL0 through PMXEVCNTR_EL0 */
static inline unsigned long read_sel_evcntr(int sel)
{
	write_sysreg(sel, pmselr_el0);
	isb();
	return read_sysreg(pmxevcntr_el0);
}

/* Write PMEVTCNTR<n>_EL0 through PMXEVCNTR_EL0 */
static inline void write_sel_evcntr(int sel, unsigned long val)
{
	write_sysreg(sel, pmselr_el0);
	isb();
	write_sysreg(val, pmxevcntr_el0);
	isb();
}

/* Read PMEVTYPER<n>_EL0 through PMXEVTYPER_EL0 */
static inline unsigned long read_sel_evtyper(int sel)
{
	write_sysreg(sel, pmselr_el0);
	isb();
	return read_sysreg(pmxevtyper_el0);
}

/* Write PMEVTYPER<n>_EL0 through PMXEVTYPER_EL0 */
static inline void write_sel_evtyper(int sel, unsigned long val)
{
	write_sysreg(sel, pmselr_el0);
	isb();
	write_sysreg(val, pmxevtyper_el0);
	isb();
}

static inline void enable_counter(int idx)
{
	uint64_t v = read_sysreg(pmcntenset_el0);

	write_sysreg(BIT(idx) | v, pmcntenset_el0);
	isb();
}

static inline void disable_counter(int idx)
{
	uint64_t v = read_sysreg(pmcntenset_el0);

	write_sysreg(BIT(idx) | v, pmcntenclr_el0);
	isb();
}

static inline uint64_t read_cycle_counter(void)
{
	return read_sysreg(pmccntr_el0);
}

static inline void reset_cycle_counter(void)
{
	uint64_t v = read_sysreg(pmcr_el0);

	write_sysreg(ARMV8_PMU_PMCR_C | v, pmcr_el0);
	isb();
}

static inline void enable_cycle_counter(void)
{
	uint64_t v = read_sysreg(pmcntenset_el0);

	write_sysreg(ARMV8_PMU_CNTENSET_C | v, pmcntenset_el0);
	isb();
}

static inline void disable_cycle_counter(void)
{
	uint64_t v = read_sysreg(pmcntenset_el0);

	write_sysreg(ARMV8_PMU_CNTENSET_C | v, pmcntenclr_el0);
	isb();
}

static inline void write_pmccfiltr(unsigned long val)
{
	write_sysreg(val, pmccfiltr_el0);
	isb();
}

static inline uint64_t read_pmccfiltr(void)
{
	return read_sysreg(pmccfiltr_el0);
}

static inline uint64_t get_pmcr_n(void)
{
	return FIELD_GET(ARMV8_PMU_PMCR_N, read_sysreg(pmcr_el0));
}

/*
 * The pmc_accessor structure has pointers to PMEV{CNTR,TYPER}<n>_EL0
 * accessors that test cases will use. Each of the accessors will
 * either directly reads/writes PMEV{CNTR,TYPER}<n>_EL0
 * (i.e. {read,write}_pmev{cnt,type}rn()), or reads/writes them through
 * PMXEV{CNTR,TYPER}_EL0 (i.e. {read,write}_sel_ev{cnt,type}r()).
 *
 * This is used to test that combinations of those accessors provide
 * the consistent behavior.
 */
struct pmc_accessor {
	/* A function to be used to read PMEVTCNTR<n>_EL0 */
	unsigned long	(*read_cntr)(int idx);
	/* A function to be used to write PMEVTCNTR<n>_EL0 */
	void		(*write_cntr)(int idx, unsigned long val);
	/* A function to be used to read PMEVTYPER<n>_EL0 */
	unsigned long	(*read_typer)(int idx);
	/* A function to be used to write PMEVTYPER<n>_EL0 */
	void		(*write_typer)(int idx, unsigned long val);
};

struct pmc_accessor pmc_accessors[] = {
	/* test with all direct accesses */
	{ read_pmevcntrn, write_pmevcntrn, read_pmevtypern, write_pmevtypern },
	/* test with all indirect accesses */
	{ read_sel_evcntr, write_sel_evcntr, read_sel_evtyper, write_sel_evtyper },
	/* read with direct accesses, and write with indirect accesses */
	{ read_pmevcntrn, write_sel_evcntr, read_pmevtypern, write_sel_evtyper },
	/* read with indirect accesses, and write with direct accesses */
	{ read_sel_evcntr, write_pmevcntrn, read_sel_evtyper, write_pmevtypern },
};

#define MAX_EVENT_FILTERS_PER_VM 10

#define EVENT_ALLOW(ev) \
	{.base_event = ev, .nevents = 1, .action = KVM_PMU_EVENT_ALLOW}

#define EVENT_DENY(ev) \
	{.base_event = ev, .nevents = 1, .action = KVM_PMU_EVENT_DENY}

#define INVALID_EC	(-1ul)
uint64_t expected_ec = INVALID_EC;
uint64_t op_end_addr;

struct vpmu_vm {
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int gic_fd;
	unsigned long *pmu_filter;
};

enum test_stage {
	TEST_STAGE_COUNTER_ACCESS = 1,
	TEST_STAGE_KVM_EVENT_FILTER,
	TEST_STAGE_KVM_EVTYPE_FILTER,
	TEST_STAGE_VCPU_MIGRATION,
};

struct guest_data {
	enum test_stage test_stage;
	uint64_t expected_pmcr_n;
	unsigned long *pmu_filter;
};

static struct guest_data guest_data;

#define VCPU_MIGRATIONS_TEST_ITERS_DEF		1000
#define VCPU_MIGRATIONS_TEST_MIGRATION_FREQ_MS	2

struct test_args {
	int vcpu_migration_test_iter;
	int vcpu_migration_test_migrate_freq_ms;
};

static struct test_args test_args = {
	.vcpu_migration_test_iter = VCPU_MIGRATIONS_TEST_ITERS_DEF,
	.vcpu_migration_test_migrate_freq_ms = VCPU_MIGRATIONS_TEST_MIGRATION_FREQ_MS,
};

static void guest_sync_handler(struct ex_regs *regs)
{
	uint64_t esr, ec;

	esr = read_sysreg(esr_el1);
	ec = (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;
	GUEST_ASSERT_4(op_end_addr && (expected_ec == ec),
		       regs->pc, esr, ec, expected_ec);

	/* Will go back to op_end_addr after the handler exits */
	regs->pc = op_end_addr;

	/*
	 * Clear op_end_addr, and setting expected_ec to INVALID_EC
	 * as a sign that an exception has occurred.
	 */
	op_end_addr = 0;
	expected_ec = INVALID_EC;
}

/*
 * Run the given operation that should trigger an exception with the
 * given exception class. The exception handler (guest_sync_handler)
 * will reset op_end_addr to 0, and expected_ec to INVALID_EC, and
 * will come back to the instruction at the @done_label.
 * The @done_label must be a unique label in this test program.
 */
#define TEST_EXCEPTION(ec, ops, done_label)		\
{							\
	extern int done_label;				\
							\
	WRITE_ONCE(op_end_addr, (uint64_t)&done_label);	\
	GUEST_ASSERT(ec != INVALID_EC);			\
	WRITE_ONCE(expected_ec, ec);			\
	dsb(ish);					\
	ops;						\
	asm volatile(#done_label":");			\
	GUEST_ASSERT(!op_end_addr);			\
	GUEST_ASSERT(expected_ec == INVALID_EC);	\
}

static void pmu_disable_reset(void)
{
	uint64_t pmcr = read_sysreg(pmcr_el0);

	/* Reset all counters, disabling them */
	pmcr &= ~ARMV8_PMU_PMCR_E;
	write_sysreg(pmcr | ARMV8_PMU_PMCR_P, pmcr_el0);
	isb();
}

static void pmu_enable(void)
{
	uint64_t pmcr = read_sysreg(pmcr_el0);

	/* Reset all counters, disabling them */
	pmcr |= ARMV8_PMU_PMCR_E;
	write_sysreg(pmcr | ARMV8_PMU_PMCR_P, pmcr_el0);
	isb();
}

static bool pmu_event_is_supported(uint64_t event)
{
	GUEST_ASSERT_1(event < 64, event);
	return (read_sysreg(pmceid0_el0) & BIT(event));
}

#define GUEST_ASSERT_BITMAP_REG(regname, mask, set_expected)		\
{									\
	uint64_t _tval = read_sysreg(regname);				\
									\
	if (set_expected)						\
		GUEST_ASSERT_3((_tval & mask), _tval, mask, set_expected); \
	else								   \
		GUEST_ASSERT_3(!(_tval & mask), _tval, mask, set_expected);\
}

/*
 * Extra instructions inserted by the compiler would be difficult to compensate
 * for, so hand assemble everything between, and including, the PMCR accesses
 * to start and stop counting. isb instructions are inserted to make sure
 * pmccntr read after this function returns the exact instructions executed
 * in the controlled block. Total instrs = isb + nop + 2*loop = 2 + 2*loop.
 */
static inline void precise_instrs_loop(int loop, uint32_t pmcr)
{
	uint64_t pmcr64 = pmcr;

	asm volatile(
	"	msr	pmcr_el0, %[pmcr]\n"
	"	isb\n"
	"1:	subs	%w[loop], %w[loop], #1\n"
	"	b.gt	1b\n"
	"	nop\n"
	"	msr	pmcr_el0, xzr\n"
	"	isb\n"
	: [loop] "+r" (loop)
	: [pmcr] "r" (pmcr64)
	: "cc");
}

/*
 * Execute a known number of guest instructions. Only even instruction counts
 * greater than or equal to 4 are supported by the in-line assembly code. The
 * control register (PMCR_EL0) is initialized with the provided value (allowing
 * for example for the cycle counter or event counters to be reset). At the end
 * of the exact instruction loop, zero is written to PMCR_EL0 to disable
 * counting, allowing the cycle counter or event counters to be read at the
 * leisure of the calling code.
 */
static void execute_precise_instrs(int num, uint32_t pmcr)
{
	int loop = (num - 2) / 2;

	GUEST_ASSERT_2(num >= 4 && ((num - 2) % 2 == 0), num, loop);
	precise_instrs_loop(loop, pmcr);
}

static void test_instructions_count(int pmc_idx, bool expect_count)
{
	int i;
	struct pmc_accessor *acc;
	uint64_t cnt;
	int instrs_count = 100;

	enable_counter(pmc_idx);

	/* Test the event using all the possible way to configure the event */
	for (i = 0; i < ARRAY_SIZE(pmc_accessors); i++) {
		acc = &pmc_accessors[i];

		pmu_disable_reset();

		acc->write_typer(pmc_idx, ARMV8_PMUV3_PERFCTR_INST_RETIRED);

		/* Enable the PMU and execute precisely number of instructions as a workload */
		execute_precise_instrs(instrs_count, read_sysreg(pmcr_el0) | ARMV8_PMU_PMCR_E);

		/* If a count is expected, the counter should be increased by 'instrs_count' */
		cnt = acc->read_cntr(pmc_idx);
		GUEST_ASSERT_4(expect_count == (cnt == instrs_count),
				i, expect_count, cnt, instrs_count);
	}

	disable_counter(pmc_idx);
}

static void test_cycles_count(bool expect_count)
{
	uint64_t cnt;

	pmu_enable();
	reset_cycle_counter();

	/* Count cycles in EL0 and EL1 */
	write_pmccfiltr(0);
	enable_cycle_counter();

	cnt = read_cycle_counter();

	/*
	 * If a count is expected by the test, the cycle counter should be increased by
	 * at least 1, as there is at least one instruction between enabling the
	 * counter and reading the counter.
	 */
	GUEST_ASSERT_2(expect_count == (cnt > 0), cnt, expect_count);

	disable_cycle_counter();
	pmu_disable_reset();
}

static void test_event_count(uint64_t event, int pmc_idx, bool expect_count)
{
	switch (event) {
	case ARMV8_PMUV3_PERFCTR_INST_RETIRED:
		test_instructions_count(pmc_idx, expect_count);
		break;
	case ARMV8_PMUV3_PERFCTR_CPU_CYCLES:
		test_cycles_count(expect_count);
		break;
	}
}

static void test_basic_pmu_functionality(void)
{
	/* Test events on generic and cycle counters */
	test_instructions_count(0, true);
	test_cycles_count(true);
}

/*
 * Check if @mask bits in {PMCNTEN,PMINTEN,PMOVS}{SET,CLR} registers
 * are set or cleared as specified in @set_expected.
 */
static void check_bitmap_pmu_regs(uint64_t mask, bool set_expected)
{
	GUEST_ASSERT_BITMAP_REG(pmcntenset_el0, mask, set_expected);
	GUEST_ASSERT_BITMAP_REG(pmcntenclr_el0, mask, set_expected);
	GUEST_ASSERT_BITMAP_REG(pmintenset_el1, mask, set_expected);
	GUEST_ASSERT_BITMAP_REG(pmintenclr_el1, mask, set_expected);
	GUEST_ASSERT_BITMAP_REG(pmovsset_el0, mask, set_expected);
	GUEST_ASSERT_BITMAP_REG(pmovsclr_el0, mask, set_expected);
}

/*
 * Check if the bit in {PMCNTEN,PMINTEN,PMOVS}{SET,CLR} registers corresponding
 * to the specified counter (@pmc_idx) can be read/written as expected.
 * When @set_op is true, it tries to set the bit for the counter in
 * those registers by writing the SET registers (the bit won't be set
 * if the counter is not implemented though).
 * Otherwise, it tries to clear the bits in the registers by writing
 * the CLR registers.
 * Then, it checks if the values indicated in the registers are as expected.
 */
static void test_bitmap_pmu_regs(int pmc_idx, bool set_op)
{
	uint64_t pmcr_n, test_bit = BIT(pmc_idx);
	bool set_expected = false;

	if (set_op) {
		write_sysreg(test_bit, pmcntenset_el0);
		write_sysreg(test_bit, pmintenset_el1);
		write_sysreg(test_bit, pmovsset_el0);

		/* The bit will be set only if the counter is implemented */
		pmcr_n = get_pmcr_n();
		set_expected = (pmc_idx < pmcr_n) ? true : false;
	} else {
		write_sysreg(test_bit, pmcntenclr_el0);
		write_sysreg(test_bit, pmintenclr_el1);
		write_sysreg(test_bit, pmovsclr_el0);
	}
	check_bitmap_pmu_regs(test_bit, set_expected);
}

/*
 * Tests for reading/writing registers for the (implemented) event counter
 * specified by @pmc_idx.
 */
static void test_access_pmc_regs(struct pmc_accessor *acc, int pmc_idx)
{
	uint64_t write_data, read_data, read_data_prev;

	/* Disable all PMCs and reset all PMCs to zero. */
	pmu_disable_reset();


	/*
	 * Tests for reading/writing {PMCNTEN,PMINTEN,PMOVS}{SET,CLR}_EL1.
	 */

	/* Make sure that the bit in those registers are set to 0 */
	test_bitmap_pmu_regs(pmc_idx, false);
	/* Test if setting the bit in those registers works */
	test_bitmap_pmu_regs(pmc_idx, true);
	/* Test if clearing the bit in those registers works */
	test_bitmap_pmu_regs(pmc_idx, false);


	/*
	 * Tests for reading/writing the event type register.
	 */

	read_data = acc->read_typer(pmc_idx);
	/*
	 * Set the event type register to an arbitrary value just for testing
	 * of reading/writing the register.
	 * ArmARM says that for the event from 0x0000 to 0x003F,
	 * the value indicated in the PMEVTYPER<n>_EL0.evtCount field is
	 * the value written to the field even when the specified event
	 * is not supported.
	 */
	write_data = (ARMV8_PMU_EXCLUDE_EL1 | ARMV8_PMUV3_PERFCTR_INST_RETIRED);
	acc->write_typer(pmc_idx, write_data);
	read_data = acc->read_typer(pmc_idx);
	GUEST_ASSERT_4(read_data == write_data,
		       pmc_idx, acc, read_data, write_data);


	/*
	 * Tests for reading/writing the event count register.
	 */

	read_data = acc->read_cntr(pmc_idx);

	/* The count value must be 0, as it is not used after the reset */
	GUEST_ASSERT_3(read_data == 0, pmc_idx, acc, read_data);

	write_data = read_data + pmc_idx + 0x12345;
	acc->write_cntr(pmc_idx, write_data);
	read_data = acc->read_cntr(pmc_idx);
	GUEST_ASSERT_4(read_data == write_data,
		       pmc_idx, acc, read_data, write_data);


	/* The following test requires the INST_RETIRED event support. */
	if (!pmu_event_is_supported(ARMV8_PMUV3_PERFCTR_INST_RETIRED))
		return;

	pmu_enable();
	acc->write_typer(pmc_idx, ARMV8_PMUV3_PERFCTR_INST_RETIRED);

	/*
	 * Make sure that the counter doesn't count the INST_RETIRED
	 * event when disabled, and the counter counts the event when enabled.
	 */
	disable_counter(pmc_idx);
	read_data_prev = acc->read_cntr(pmc_idx);
	read_data = acc->read_cntr(pmc_idx);
	GUEST_ASSERT_4(read_data == read_data_prev,
		       pmc_idx, acc, read_data, read_data_prev);

	enable_counter(pmc_idx);
	read_data = acc->read_cntr(pmc_idx);

	/*
	 * The counter should be increased by at least 1, as there is at
	 * least one instruction between enabling the counter and reading
	 * the counter (the test assumes that all event counters are not
	 * being used by the host's higher priority events).
	 */
	GUEST_ASSERT_4(read_data > read_data_prev,
		       pmc_idx, acc, read_data, read_data_prev);
}

/*
 * Tests for reading/writing registers for the unimplemented event counter
 * specified by @pmc_idx (>= PMCR_EL0.N).
 */
static void test_access_invalid_pmc_regs(struct pmc_accessor *acc, int pmc_idx)
{
	/*
	 * Reading/writing the event count/type registers should cause
	 * an UNDEFINED exception.
	 */
	TEST_EXCEPTION(ESR_EC_UNKNOWN, acc->read_cntr(pmc_idx), inv_rd_cntr);
	TEST_EXCEPTION(ESR_EC_UNKNOWN, acc->write_cntr(pmc_idx, 0), inv_wr_cntr);
	TEST_EXCEPTION(ESR_EC_UNKNOWN, acc->read_typer(pmc_idx), inv_rd_typer);
	TEST_EXCEPTION(ESR_EC_UNKNOWN, acc->write_typer(pmc_idx, 0), inv_wr_typer);
	/*
	 * The bit corresponding to the (unimplemented) counter in
	 * {PMCNTEN,PMOVS}{SET,CLR}_EL1 registers should be RAZ.
	 */
	test_bitmap_pmu_regs(pmc_idx, 1);
	test_bitmap_pmu_regs(pmc_idx, 0);
}

/*
 * The guest is configured with PMUv3 with @expected_pmcr_n number of
 * event counters.
 * Check if @expected_pmcr_n is consistent with PMCR_EL0.N, and
 * if reading/writing PMU registers for implemented or unimplemented
 * counters can work as expected.
 */
static void guest_counter_access_test(uint64_t expected_pmcr_n)
{
	uint64_t pmcr_n, unimp_mask;
	int i, pmc;

	GUEST_ASSERT(expected_pmcr_n <= ARMV8_PMU_MAX_GENERAL_COUNTERS);

	pmcr_n = get_pmcr_n();

	/* Make sure that PMCR_EL0.N indicates the value userspace set */
	GUEST_ASSERT_2(pmcr_n == expected_pmcr_n, pmcr_n, expected_pmcr_n);

	/*
	 * Make sure that (RAZ) bits corresponding to unimplemented event
	 * counters in {PMCNTEN,PMOVS}{SET,CLR}_EL1 registers are reset to zero.
	 * (NOTE: bits for implemented event counters are reset to UNKNOWN)
	 */
	unimp_mask = GENMASK_ULL(ARMV8_PMU_MAX_GENERAL_COUNTERS - 1, pmcr_n);
	check_bitmap_pmu_regs(unimp_mask, false);

	/*
	 * Tests for reading/writing PMU registers for implemented counters.
	 * Use each combination of PMEV{CNTR,TYPER}<n>_EL0 accessor functions.
	 */
	for (i = 0; i < ARRAY_SIZE(pmc_accessors); i++) {
		for (pmc = 0; pmc < pmcr_n; pmc++)
			test_access_pmc_regs(&pmc_accessors[i], pmc);
	}

	/*
	 * Tests for reading/writing PMU registers for unimplemented counters.
	 * Use each combination of PMEV{CNTR,TYPER}<n>_EL0 accessor functions.
	 */
	for (i = 0; i < ARRAY_SIZE(pmc_accessors); i++) {
		for (pmc = pmcr_n; pmc < ARMV8_PMU_MAX_GENERAL_COUNTERS; pmc++)
			test_access_invalid_pmc_regs(&pmc_accessors[i], pmc);
	}
}

static void guest_event_filter_test(unsigned long *pmu_filter)
{
	uint64_t event;

	/*
	 * Check if PMCEIDx_EL0 is advertized as configured by the userspace.
	 * It's possible that even though the userspace allowed it, it may not be supported
	 * by the hardware and could be advertized as 'disabled'. Hence, only validate against
	 * the events that are advertized.
	 *
	 * Furthermore, check if the event is in fact counting if enabled, or vice-versa.
	 */
	for (event = 0; event < ARMV8_PMU_MAX_EVENTS - 1; event++) {
		if (pmu_event_is_supported(event)) {
			GUEST_ASSERT_1(test_bit(event, pmu_filter), event);
			test_event_count(event, 0, true);
		} else {
			test_event_count(event, 0, false);
		}
	}
}

static void guest_evtype_filter_test(void)
{
	int i;
	struct pmc_accessor *acc;
	uint64_t typer, cnt;
	struct arm_smccc_res res;

	pmu_enable();

	/*
	 * KVM blocks the guests from creating events for counting in Secure/Non-Secure Hyp (EL2),
	 * Monitor (EL3), and Multithreading configuration. It applies the mask
	 * ARMV8_PMU_EVTYPE_MASK against guest accesses to PMXEVTYPER_EL0, PMEVTYPERn_EL0,
	 * and PMCCFILTR_EL0 registers to prevent this. Check if KVM honors this using all possible
	 * ways to configure the EVTYPER.
	 */
	for (i = 0; i < ARRAY_SIZE(pmc_accessors); i++) {
		acc = &pmc_accessors[i];

		/* Set all filter bits (31-24), readback, and check against the mask */
		acc->write_typer(0, 0xff000000);
		typer = acc->read_typer(0);

		GUEST_ASSERT_2((typer | ARMV8_PMU_EVTYPE_EVENT) == ARMV8_PMU_EVTYPE_MASK,
				typer | ARMV8_PMU_EVTYPE_EVENT, ARMV8_PMU_EVTYPE_MASK);

		/*
		 * Regardless of ARMV8_PMU_EVTYPE_MASK, KVM sets perf attr.exclude_hv
		 * to not count NS-EL2 events. Verify this functionality by configuring
		 * a NS-EL2 event, for which the couunt shouldn't increment.
		 */
		typer = ARMV8_PMUV3_PERFCTR_INST_RETIRED;
		typer |= ARMV8_PMU_INCLUDE_EL2 | ARMV8_PMU_EXCLUDE_EL1 | ARMV8_PMU_EXCLUDE_EL0;
		acc->write_typer(0, typer);
		acc->write_cntr(0, 0);
		enable_counter(0);

		/* Issue a hypercall to enter EL2 and return */
		memset(&res, 0, sizeof(res));
		smccc_hvc(ARM_SMCCC_VERSION_FUNC_ID, 0, 0, 0, 0, 0, 0, 0, &res);

		cnt = acc->read_cntr(0);
		GUEST_ASSERT_3(cnt == 0, cnt, typer, i);
	}

	/* Check the same sequence for the Cycle counter */
	write_pmccfiltr(0xff000000);
	typer = read_pmccfiltr();
	GUEST_ASSERT_2((typer | ARMV8_PMU_EVTYPE_EVENT) == ARMV8_PMU_EVTYPE_MASK,
				typer | ARMV8_PMU_EVTYPE_EVENT, ARMV8_PMU_EVTYPE_MASK);

	typer = ARMV8_PMU_INCLUDE_EL2 | ARMV8_PMU_EXCLUDE_EL1 | ARMV8_PMU_EXCLUDE_EL0;
	write_pmccfiltr(typer);
	reset_cycle_counter();
	enable_cycle_counter();

	/* Issue a hypercall to enter EL2 and return */
	memset(&res, 0, sizeof(res));
	smccc_hvc(ARM_SMCCC_VERSION_FUNC_ID, 0, 0, 0, 0, 0, 0, 0, &res);

	cnt = read_cycle_counter();
	GUEST_ASSERT_2(cnt == 0, cnt, typer);
}

static void guest_vcpu_migration_test(void)
{
	/*
	 * While the userspace continuously migrates this vCPU to random pCPUs,
	 * run basic PMU functionalities and verify the results.
	 */
	while (test_args.vcpu_migration_test_iter--)
		test_basic_pmu_functionality();
}

static void guest_code(void)
{
	switch (guest_data.test_stage) {
	case TEST_STAGE_COUNTER_ACCESS:
		guest_counter_access_test(guest_data.expected_pmcr_n);
		break;
	case TEST_STAGE_KVM_EVENT_FILTER:
		guest_event_filter_test(guest_data.pmu_filter);
		break;
	case TEST_STAGE_KVM_EVTYPE_FILTER:
		guest_evtype_filter_test();
		break;
	case TEST_STAGE_VCPU_MIGRATION:
		guest_vcpu_migration_test();
		break;
	default:
		GUEST_ASSERT_1(0, guest_data.test_stage);
	}

	GUEST_DONE();
}

#define GICD_BASE_GPA	0x8000000ULL
#define GICR_BASE_GPA	0x80A0000ULL

static unsigned long *
set_event_filters(struct kvm_vcpu *vcpu, struct kvm_pmu_event_filter *pmu_event_filters)
{
	int j;
	unsigned long *pmu_filter;
	struct kvm_device_attr filter_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_FILTER,
	};

	/*
	 * Setting up of the bitmap is similar to what KVM does.
	 * If the first filter denys an event, default all the others to allow, and vice-versa.
	 */
	pmu_filter = bitmap_zalloc(ARMV8_PMU_MAX_EVENTS);
	TEST_ASSERT(pmu_filter, "Failed to allocate the pmu_filter");

	if (pmu_event_filters[0].action == KVM_PMU_EVENT_DENY)
		bitmap_fill(pmu_filter, ARMV8_PMU_MAX_EVENTS);

	for (j = 0; j < MAX_EVENT_FILTERS_PER_VM; j++) {
		struct kvm_pmu_event_filter *pmu_event_filter = &pmu_event_filters[j];

		if (!pmu_event_filter->nevents)
			break;

		pr_debug("Applying event filter:: event: 0x%x; action: %s\n",
				pmu_event_filter->base_event,
				pmu_event_filter->action == KVM_PMU_EVENT_ALLOW ? "ALLOW" : "DENY");

		filter_attr.addr = (uint64_t) pmu_event_filter;
		vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &filter_attr);

		if (pmu_event_filter->action == KVM_PMU_EVENT_ALLOW)
			__set_bit(pmu_event_filter->base_event, pmu_filter);
		else
			__clear_bit(pmu_event_filter->base_event, pmu_filter);
	}

	return pmu_filter;
}

/* Create a VM that has one vCPU with PMUv3 configured. */
static struct vpmu_vm *
create_vpmu_vm(void *guest_code, struct kvm_pmu_event_filter *pmu_event_filters)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_init init;
	uint8_t pmuver, ec;
	uint64_t dfr0, irq = 23;
	struct vpmu_vm *vpmu_vm;
	struct kvm_device_attr irq_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_IRQ,
		.addr = (uint64_t)&irq,
	};
	struct kvm_device_attr init_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_INIT,
	};

	vpmu_vm = calloc(1, sizeof(*vpmu_vm));
	TEST_ASSERT(vpmu_vm, "Failed to allocate vpmu_vm");

	vpmu_vm->vm = vm = vm_create(1);
	vm_init_descriptor_tables(vm);

	/* Catch exceptions for easier debugging */
	for (ec = 0; ec < ESR_EC_NUM; ec++) {
		vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT, ec,
					guest_sync_handler);
	}

	/* Create vCPU with PMUv3 */
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= (1 << KVM_ARM_VCPU_PMU_V3);
	vpmu_vm->vcpu = vcpu = aarch64_vcpu_add(vm, 0, &init, guest_code);
	vcpu_init_descriptor_tables(vcpu);
	vpmu_vm->gic_fd = vgic_v3_setup(vm, 1, 64, GICD_BASE_GPA, GICR_BASE_GPA);

	/* Make sure that PMUv3 support is indicated in the ID register */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_ID_AA64DFR0_EL1), &dfr0);
	pmuver = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMUVER), dfr0);
	TEST_ASSERT(pmuver != ID_AA64DFR0_PMUVER_IMP_DEF &&
		    pmuver >= ID_AA64DFR0_PMUVER_8_0,
		    "Unexpected PMUVER (0x%x) on the vCPU with PMUv3", pmuver);

	/* Initialize vPMU */
	if (pmu_event_filters)
		vpmu_vm->pmu_filter = set_event_filters(vcpu, pmu_event_filters);

	vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &irq_attr);
	vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &init_attr);

	return vpmu_vm;
}

static void destroy_vpmu_vm(struct vpmu_vm *vpmu_vm)
{
	if (vpmu_vm->pmu_filter)
		bitmap_free(vpmu_vm->pmu_filter);
	close(vpmu_vm->gic_fd);
	kvm_vm_free(vpmu_vm->vm);
	free(vpmu_vm);
}

static void run_vcpu(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	sync_global_to_guest(vcpu->vm, guest_data);
	sync_global_to_guest(vcpu->vm, test_args);

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT_4(uc, "values:%#lx %#lx %#lx %#lx");
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
static void run_counter_access_test(uint64_t pmcr_n)
{
	struct vpmu_vm *vpmu_vm;
	struct kvm_vcpu *vcpu;
	uint64_t sp, pmcr, pmcr_orig;
	struct kvm_vcpu_init init;

	guest_data.expected_pmcr_n = pmcr_n;

	pr_debug("Test with pmcr_n %lu\n", pmcr_n);
	vpmu_vm = create_vpmu_vm(guest_code, NULL);
	vcpu = vpmu_vm->vcpu;

	/* Save the initial sp to restore them later to run the guest again */
	vcpu_get_reg(vcpu, ARM64_CORE_REG(sp_el1), &sp);

	/* Update the PMCR_EL0.N with @pmcr_n */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr_orig);
	pmcr = pmcr_orig & ~ARMV8_PMU_PMCR_N;
	pmcr |= (pmcr_n << ARMV8_PMU_PMCR_N_SHIFT);
	vcpu_set_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), pmcr);

	run_vcpu(vcpu);

	/*
	 * Reset and re-initialize the vCPU, and run the guest code again to
	 * check if PMCR_EL0.N is preserved.
	 */
	vm_ioctl(vpmu_vm->vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= (1 << KVM_ARM_VCPU_PMU_V3);
	aarch64_vcpu_setup(vcpu, &init);
	vcpu_init_descriptor_tables(vcpu);
	vcpu_set_reg(vcpu, ARM64_CORE_REG(sp_el1), sp);
	vcpu_set_reg(vcpu, ARM64_CORE_REG(regs.pc), (uint64_t)guest_code);

	run_vcpu(vcpu);

	destroy_vpmu_vm(vpmu_vm);
}

/*
 * Create a guest with one vCPU, and attempt to set the PMCR_EL0.N for
 * the vCPU to @pmcr_n, which is larger than the host value.
 * The attempt should fail as @pmcr_n is too big to set for the vCPU.
 */
static void run_counter_access_error_test(uint64_t pmcr_n)
{
	struct vpmu_vm *vpmu_vm;
	struct kvm_vcpu *vcpu;
	int ret;
	uint64_t pmcr, pmcr_orig;

	guest_data.expected_pmcr_n = pmcr_n;

	pr_debug("Error test with pmcr_n %lu (larger than the host)\n", pmcr_n);
	vpmu_vm = create_vpmu_vm(guest_code, NULL);
	vcpu = vpmu_vm->vcpu;

	/* Update the PMCR_EL0.N with @pmcr_n */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr_orig);
	pmcr = pmcr_orig & ~ARMV8_PMU_PMCR_N;
	pmcr |= (pmcr_n << ARMV8_PMU_PMCR_N_SHIFT);

	/* This should fail as @pmcr_n is too big to set for the vCPU */
	ret = __vcpu_set_reg(vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), pmcr);
	TEST_ASSERT(ret, "Setting PMCR to 0x%lx (orig PMCR 0x%lx) didn't fail",
		    pmcr, pmcr_orig);

	destroy_vpmu_vm(vpmu_vm);
}

static void run_counter_access_tests(uint64_t pmcr_n)
{
	uint64_t i;

	guest_data.test_stage = TEST_STAGE_COUNTER_ACCESS;

	for (i = 0; i <= pmcr_n; i++)
		run_counter_access_test(i);

	for (i = pmcr_n + 1; i < ARMV8_PMU_MAX_COUNTERS; i++)
		run_counter_access_error_test(i);
}

static struct kvm_pmu_event_filter pmu_event_filters[][MAX_EVENT_FILTERS_PER_VM] = {
	/*
	 * Each set of events denotes a filter configuration for that VM.
	 * During VM creation, the filters will be applied in the sequence mentioned here.
	 */
	{
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
	},
	{
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
	},
	{
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
	},
	{
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
	},
	{
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
	},
	{
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
		EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
	},
	{
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_CPU_CYCLES),
	},
	{
		EVENT_DENY(ARMV8_PMUV3_PERFCTR_INST_RETIRED),
	},
};

static void run_kvm_event_filter_error_tests(void)
{
	int ret;
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vpmu_vm *vpmu_vm;
	struct kvm_vcpu_init init;
	struct kvm_pmu_event_filter pmu_event_filter = EVENT_ALLOW(ARMV8_PMUV3_PERFCTR_CPU_CYCLES);
	struct kvm_device_attr filter_attr = {
		.group = KVM_ARM_VCPU_PMU_V3_CTRL,
		.attr = KVM_ARM_VCPU_PMU_V3_FILTER,
		.addr = (uint64_t) &pmu_event_filter,
	};

	/* KVM should not allow configuring filters after the PMU is initialized */
	vpmu_vm = create_vpmu_vm(guest_code, NULL);
	ret = __vcpu_ioctl(vpmu_vm->vcpu, KVM_SET_DEVICE_ATTR, &filter_attr);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
			"Failed to disallow setting an event filter after PMU init");
	destroy_vpmu_vm(vpmu_vm);

	/* Check for invalid event filter setting */
	vm = vm_create(1);
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] |= (1 << KVM_ARM_VCPU_PMU_V3);
	vcpu = aarch64_vcpu_add(vm, 0, &init, guest_code);

	pmu_event_filter.base_event = UINT16_MAX;
	pmu_event_filter.nevents = 5;
	ret = __vcpu_ioctl(vcpu, KVM_SET_DEVICE_ATTR, &filter_attr);
	TEST_ASSERT(ret == -1 && errno == EINVAL, "Failed check for invalid filter configuration");
	kvm_vm_free(vm);
}

static void run_kvm_event_filter_test(void)
{
	int i;
	struct vpmu_vm *vpmu_vm;
	struct kvm_vm *vm;
	vm_vaddr_t pmu_filter_gva;
	size_t pmu_filter_bmap_sz = BITS_TO_LONGS(ARMV8_PMU_MAX_EVENTS) * sizeof(unsigned long);

	guest_data.test_stage = TEST_STAGE_KVM_EVENT_FILTER;

	/* Test for valid filter configurations */
	for (i = 0; i < ARRAY_SIZE(pmu_event_filters); i++) {
		vpmu_vm = create_vpmu_vm(guest_code, pmu_event_filters[i]);
		vm = vpmu_vm->vm;

		pmu_filter_gva = vm_vaddr_alloc(vm, pmu_filter_bmap_sz, KVM_UTIL_MIN_VADDR);
		memcpy(addr_gva2hva(vm, pmu_filter_gva), vpmu_vm->pmu_filter, pmu_filter_bmap_sz);
		guest_data.pmu_filter = (unsigned long *) pmu_filter_gva;

		run_vcpu(vpmu_vm->vcpu);

		destroy_vpmu_vm(vpmu_vm);
	}

	/* Check if KVM is handling the errors correctly */
	run_kvm_event_filter_error_tests();
}

static void run_kvm_evtype_filter_test(void)
{
	struct vpmu_vm *vpmu_vm;

	guest_data.test_stage = TEST_STAGE_KVM_EVTYPE_FILTER;

	vpmu_vm = create_vpmu_vm(guest_code, NULL);
	run_vcpu(vpmu_vm->vcpu);
	destroy_vpmu_vm(vpmu_vm);
}

struct vcpu_migrate_data {
	struct vpmu_vm *vpmu_vm;
	pthread_t *pt_vcpu;
	bool vcpu_done;
};

static void *run_vcpus_migrate_test_func(void *arg)
{
	struct vcpu_migrate_data *migrate_data = arg;
	struct vpmu_vm *vpmu_vm = migrate_data->vpmu_vm;

	run_vcpu(vpmu_vm->vcpu);
	migrate_data->vcpu_done = true;

	return NULL;
}

static uint32_t get_pcpu(void)
{
	uint32_t pcpu;
	unsigned int nproc_conf;
	cpu_set_t online_cpuset;

	nproc_conf = get_nprocs_conf();
	sched_getaffinity(0, sizeof(cpu_set_t), &online_cpuset);

	/* Randomly find an available pCPU to place the vCPU on */
	do {
		pcpu = rand() % nproc_conf;
	} while (!CPU_ISSET(pcpu, &online_cpuset));

	return pcpu;
}

static int migrate_vcpu(struct vcpu_migrate_data *migrate_data)
{
	int ret;
	cpu_set_t cpuset;
	uint32_t new_pcpu = get_pcpu();

	CPU_ZERO(&cpuset);
	CPU_SET(new_pcpu, &cpuset);

	pr_debug("Migrating vCPU to pCPU: %u\n", new_pcpu);

	ret = pthread_setaffinity_np(*migrate_data->pt_vcpu, sizeof(cpuset), &cpuset);

	/* Allow the error where the vCPU thread is already finished */
	TEST_ASSERT(ret == 0 || ret == ESRCH,
		    "Failed to migrate the vCPU to pCPU: %u; ret: %d\n", new_pcpu, ret);

	return ret;
}

static void *vcpus_migrate_func(void *arg)
{
	struct vcpu_migrate_data *migrate_data = arg;

	while (!migrate_data->vcpu_done) {
		usleep(msecs_to_usecs(test_args.vcpu_migration_test_migrate_freq_ms));
		migrate_vcpu(migrate_data);
	}

	return NULL;
}

static void run_vcpu_migration_test(uint64_t pmcr_n)
{
	int ret;
	struct vpmu_vm *vpmu_vm;
	pthread_t pt_vcpu, pt_sched;
	struct vcpu_migrate_data migrate_data = {
		.pt_vcpu = &pt_vcpu,
		.vcpu_done = false,
	};

	__TEST_REQUIRE(get_nprocs() >= 2, "At least two pCPUs needed for vCPU migration test");

	guest_data.test_stage = TEST_STAGE_VCPU_MIGRATION;
	guest_data.expected_pmcr_n = pmcr_n;

	migrate_data.vpmu_vm = vpmu_vm = create_vpmu_vm(guest_code, NULL);

	/* Initialize random number generation for migrating vCPUs to random pCPUs */
	srand(time(NULL));

	/* Spawn a vCPU thread */
	ret = pthread_create(&pt_vcpu, NULL, run_vcpus_migrate_test_func, &migrate_data);
	TEST_ASSERT(!ret, "Failed to create the vCPU thread");

	/* Spawn a scheduler thread to force-migrate vCPUs to various pCPUs */
	ret = pthread_create(&pt_sched, NULL, vcpus_migrate_func, &migrate_data);
	TEST_ASSERT(!ret, "Failed to create the scheduler thread for migrating the vCPUs");

	pthread_join(pt_sched, NULL);
	pthread_join(pt_vcpu, NULL);

	destroy_vpmu_vm(vpmu_vm);
}

static void run_tests(uint64_t pmcr_n)
{
	run_counter_access_tests(pmcr_n);
	run_kvm_event_filter_test();
	run_kvm_evtype_filter_test();
	run_vcpu_migration_test(pmcr_n);
}

/*
 * Return the default number of implemented PMU event counters excluding
 * the cycle counter (i.e. PMCR_EL0.N value) for the guest.
 */
static uint64_t get_pmcr_n_limit(void)
{
	struct vpmu_vm *vpmu_vm;
	uint64_t pmcr;

	vpmu_vm = create_vpmu_vm(guest_code, NULL);
	vcpu_get_reg(vpmu_vm->vcpu, KVM_ARM64_SYS_REG(SYS_PMCR_EL0), &pmcr);
	destroy_vpmu_vm(vpmu_vm);

	return FIELD_GET(ARMV8_PMU_PMCR_N, pmcr);
}

static void print_help(char *name)
{
	pr_info("Usage: %s [-h] [-i vcpu_migration_test_iterations] [-m vcpu_migration_freq_ms]\n",
		name);
	pr_info("\t-i: Number of iterations of vCPU migrations test (default: %u)\n",
		VCPU_MIGRATIONS_TEST_ITERS_DEF);
	pr_info("\t-m: Frequency (in ms) of vCPUs to migrate to different pCPU. (default: %u)\n",
		VCPU_MIGRATIONS_TEST_MIGRATION_FREQ_MS);
	pr_info("\t-h: print this help screen\n");
}

static bool parse_args(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "hi:m:")) != -1) {
		switch (opt) {
		case 'i':
			test_args.vcpu_migration_test_iter =
				atoi_positive("Nr vCPU migration iterations", optarg);
			break;
		case 'm':
			test_args.vcpu_migration_test_migrate_freq_ms =
				atoi_positive("vCPU migration frequency", optarg);
			break;
		case 'h':
		default:
			goto err;
		}
	}

	return true;

err:
	print_help(argv[0]);
	return false;
}

int main(int argc, char *argv[])
{
	uint64_t pmcr_n;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_PMU_V3));

	if (!parse_args(argc, argv))
		exit(KSFT_SKIP);

	pmcr_n = get_pmcr_n_limit();
	run_tests(pmcr_n);

	return 0;
}
