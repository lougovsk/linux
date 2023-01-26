/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_PMUV3_H
#define __ASM_PMUV3_H

#include <asm/cp15.h>
#include <asm/cputype.h>

#define PMCCNTR			__ACCESS_CP15_64(0, c9)

#define PMCR			__ACCESS_CP15(c9,  0, c12, 0)
#define PMCNTENSET		__ACCESS_CP15(c9,  0, c12, 1)
#define PMCNTENCLR		__ACCESS_CP15(c9,  0, c12, 2)
#define PMOVSR			__ACCESS_CP15(c9,  0, c12, 3)
#define PMSELR			__ACCESS_CP15(c9,  0, c12, 5)
#define PMCEID0			__ACCESS_CP15(c9,  0, c12, 6)
#define PMCEID1			__ACCESS_CP15(c9,  0, c12, 7)
#define PMXEVTYPER		__ACCESS_CP15(c9,  0, c13, 1)
#define PMXEVCNTR		__ACCESS_CP15(c9,  0, c13, 2)
#define PMUSERENR		__ACCESS_CP15(c9,  0, c14, 0)
#define PMINTENSET		__ACCESS_CP15(c9,  0, c14, 1)
#define PMINTENCLR		__ACCESS_CP15(c9,  0, c14, 2)
#define PMMIR			__ACCESS_CP15(c9,  0, c14, 6)
#define PMCCFILTR		__ACCESS_CP15(c14, 0, c15, 7)
#define PMEVCNTR0(n)	__ACCESS_CP15(c14, 0, c8, n)
#define PMEVCNTR1(n)	__ACCESS_CP15(c14, 0, c9, n)
#define PMEVCNTR2(n)	__ACCESS_CP15(c14, 0, c10, n)
#define PMEVCNTR3(n)	__ACCESS_CP15(c14, 0, c11, n)
#define PMEVTYPER0(n)	__ACCESS_CP15(c14, 0, c12, n)
#define PMEVTYPER1(n)	__ACCESS_CP15(c14, 0, c13, n)
#define PMEVTYPER2(n)	__ACCESS_CP15(c14, 0, c14, n)
#define PMEVTYPER3(n)	__ACCESS_CP15(c14, 0, c15, n)

#define PMEV_EVENTS_PER_REG		8
#define PMEV_REGISTER(n)		(n / PMEV_EVENTS_PER_REG)
#define PMEV_EVENT(n)			(n % PMEV_EVENTS_PER_REG)

#define PMEV_CASE(reg, ev, case_macro)	\
	case ev:							\
		case_macro(reg, ev);			\
		break

#define PMEV_EV_SWITCH(reg, ev, case_macro)	\
	do {									\
		switch (ev) {						\
		PMEV_CASE(reg, 0, case_macro);		\
		PMEV_CASE(reg, 1, case_macro);		\
		PMEV_CASE(reg, 2, case_macro);		\
		PMEV_CASE(reg, 3, case_macro);		\
		PMEV_CASE(reg, 4, case_macro);		\
		PMEV_CASE(reg, 5, case_macro);		\
		PMEV_CASE(reg, 6, case_macro);		\
		PMEV_CASE(reg, 7, case_macro);		\
		default:	\
			WARN(1, "Invalid PMEV* event index\n");	\
		}									\
	} while (0)

#define PMEV_REG_SWITCH(reg, ev, case_macro)	\
	do {										\
		switch (reg) {							\
		case 0:									\
			PMEV_EV_SWITCH(0, ev, case_macro);	\
			break;								\
		case 1:									\
			PMEV_EV_SWITCH(1, ev, case_macro);	\
			break;								\
		case 2:									\
			PMEV_EV_SWITCH(2, ev, case_macro);	\
			break;								\
		case 3:									\
			PMEV_EV_SWITCH(3, ev, case_macro);	\
			break;								\
		default:								\
			WARN(1, "Invalid PMEV* register index\n");	\
		}										\
	} while (0)

#define RETURN_READ_PMEVCNTR(reg, ev) \
	return read_sysreg(PMEVCNTR##reg(ev))
static unsigned long read_pmevcntrn(int n)
{
	const int reg = PMEV_REGISTER(n);
	const int event = PMEV_EVENT(n);

	PMEV_REG_SWITCH(reg, event, RETURN_READ_PMEVCNTR);
	return 0;
}

#define WRITE_PMEVCNTR(reg, ev) \
	write_sysreg(val, PMEVCNTR##reg(ev))
static void write_pmevcntrn(int n, unsigned long val)
{
	const int reg = PMEV_REGISTER(n);
	const int event = PMEV_EVENT(n);

	PMEV_REG_SWITCH(reg, event, WRITE_PMEVCNTR);
}

#define WRITE_PMEVTYPER(reg, ev) \
	write_sysreg(val, PMEVTYPER##reg(ev))
static void write_pmevtypern(int n, unsigned long val)
{
	const int reg = PMEV_REGISTER(n);
	const int event = PMEV_EVENT(n);

	PMEV_REG_SWITCH(reg, event, WRITE_PMEVTYPER);
}

static inline unsigned long read_pmmir(void)
{
	return read_sysreg(PMMIR);
}

static inline u32 read_pmuver(void)
{
	/* PMUVers is not a signed field */
	u32 dfr0 = read_cpuid_ext(CPUID_EXT_DFR0);

	return (dfr0 >> 24) & 0xf;
}

static inline void write_pmcr(u32 val)
{
	write_sysreg(val, PMCR);
}

static inline u32 read_pmcr(void)
{
	return read_sysreg(PMCR);
}

static inline void write_pmselr(u32 val)
{
	write_sysreg(val, PMSELR);
}

static inline void write_pmccntr(u64 val)
{
	write_sysreg(val, PMCCNTR);
}

static inline u64 read_pmccntr(void)
{
	return read_sysreg(PMCCNTR);
}

static inline void write_pmxevcntr(u32 val)
{
	write_sysreg(val, PMXEVCNTR);
}

static inline u32 read_pmxevcntr(void)
{
	return read_sysreg(PMXEVCNTR);
}

static inline void write_pmxevtyper(u32 val)
{
	write_sysreg(val, PMXEVTYPER);
}

static inline void write_pmcntenset(u32 val)
{
	write_sysreg(val, PMCNTENSET);
}

static inline void write_pmcntenclr(u32 val)
{
	write_sysreg(val, PMCNTENCLR);
}

static inline void write_pmintenset(u32 val)
{
	write_sysreg(val, PMINTENSET);
}

static inline void write_pmintenclr(u32 val)
{
	write_sysreg(val, PMINTENCLR);
}

static inline void write_pmccfiltr(u32 val)
{
	write_sysreg(val, PMCCFILTR);
}

static inline void write_pmovsclr(u32 val)
{
	write_sysreg(val, PMOVSR);
}

static inline u32 read_pmovsclr(void)
{
	return read_sysreg(PMOVSR);
}

static inline void write_pmuserenr(u32 val)
{
	write_sysreg(val, PMUSERENR);
}

static inline u32 read_pmceid0(void)
{
	return read_sysreg(PMCEID0);
}

static inline u32 read_pmceid1(void)
{
	return read_sysreg(PMCEID1);
}

static inline void
armv8pmu_kvm_set_events(u32 set, struct perf_event_attr *attr) {}

static inline void armv8pmu_kvm_clr_events(u32 clr) {}

static inline bool armv8pmu_kvm_counter_deferred(struct perf_event_attr *attr)
{
	return false;
}

#endif
