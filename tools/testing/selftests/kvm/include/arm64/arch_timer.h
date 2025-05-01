/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ARM Generic Timer specific interface
 */

#ifndef SELFTEST_KVM_ARCH_TIMER_H
#define SELFTEST_KVM_ARCH_TIMER_H

#include "processor.h"

enum arch_timer {
	VIRTUAL,
	PHYSICAL,
};

#define CTL_ENABLE	(1 << 0)
#define CTL_IMASK	(1 << 1)
#define CTL_ISTATUS	(1 << 2)

#define msec_to_cycles(msec)	\
	(timer_get_cntfrq() * (u64)(msec) / 1000)

#define usec_to_cycles(usec)	\
	(timer_get_cntfrq() * (u64)(usec) / 1000000)

#define cycles_to_usec(cycles) \
	((u64)(cycles) * 1000000 / timer_get_cntfrq())

static inline u32 timer_get_cntfrq(void)
{
	return read_sysreg(cntfrq_el0);
}

static inline u64 timer_get_cntct(enum arch_timer timer)
{
	isb();

	switch (timer) {
	case VIRTUAL:
		return read_sysreg(cntvct_el0);
	case PHYSICAL:
		return read_sysreg(cntpct_el0);
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	/* We should not reach here */
	return 0;
}

static inline void timer_set_cval(enum arch_timer timer, u64 cval)
{
	switch (timer) {
	case VIRTUAL:
		write_sysreg(cval, cntv_cval_el0);
		break;
	case PHYSICAL:
		write_sysreg(cval, cntp_cval_el0);
		break;
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	isb();
}

static inline u64 timer_get_cval(enum arch_timer timer)
{
	switch (timer) {
	case VIRTUAL:
		return read_sysreg(cntv_cval_el0);
	case PHYSICAL:
		return read_sysreg(cntp_cval_el0);
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	/* We should not reach here */
	return 0;
}

static inline void timer_set_tval(enum arch_timer timer, s32 tval)
{
	switch (timer) {
	case VIRTUAL:
		write_sysreg(tval, cntv_tval_el0);
		break;
	case PHYSICAL:
		write_sysreg(tval, cntp_tval_el0);
		break;
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	isb();
}

static inline s32 timer_get_tval(enum arch_timer timer)
{
	isb();
	switch (timer) {
	case VIRTUAL:
		return read_sysreg(cntv_tval_el0);
	case PHYSICAL:
		return read_sysreg(cntp_tval_el0);
	default:
		GUEST_FAIL("Could not get timer %d\n", timer);
	}

	/* We should not reach here */
	return 0;
}

static inline void timer_set_ctl(enum arch_timer timer, u32 ctl)
{
	switch (timer) {
	case VIRTUAL:
		write_sysreg(ctl, cntv_ctl_el0);
		break;
	case PHYSICAL:
		write_sysreg(ctl, cntp_ctl_el0);
		break;
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	isb();
}

static inline u32 timer_get_ctl(enum arch_timer timer)
{
	switch (timer) {
	case VIRTUAL:
		return read_sysreg(cntv_ctl_el0);
	case PHYSICAL:
		return read_sysreg(cntp_ctl_el0);
	default:
		GUEST_FAIL("Unexpected timer type = %u", timer);
	}

	/* We should not reach here */
	return 0;
}

static inline void timer_set_next_cval_ms(enum arch_timer timer, u32 msec)
{
	u64 now_ct = timer_get_cntct(timer);
	u64 next_ct = now_ct + msec_to_cycles(msec);

	timer_set_cval(timer, next_ct);
}

static inline void timer_set_next_tval_ms(enum arch_timer timer, u32 msec)
{
	timer_set_tval(timer, msec_to_cycles(msec));
}

#endif /* SELFTEST_KVM_ARCH_TIMER_H */
