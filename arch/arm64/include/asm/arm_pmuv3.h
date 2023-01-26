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

#include <asm/cpufeature.h>
#include <asm/sysreg.h>

/*
 * This code is really good
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
		default: WARN(1, "Invalid PMEV* index\n");	\
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
}

#define WRITE_PMEVTYPERN(n) \
	write_sysreg(val, pmevtyper##n##_el0)
static void write_pmevtypern(int n, unsigned long val)
{
	PMEVN_SWITCH(n, WRITE_PMEVTYPERN);
}

static inline unsigned long read_pmmir(void)
{
	return read_cpuid(PMMIR_EL1);
}

static inline u32 read_pmuver(void)
{
	u64 dfr0 = read_sysreg(id_aa64dfr0_el1);

	return cpuid_feature_extract_unsigned_field(dfr0,
			ID_AA64DFR0_EL1_PMUVer_SHIFT);
}

static inline void write_pmcr(u32 val)
{
	write_sysreg(val, pmcr_el0);
}

static inline u32 read_pmcr(void)
{
	return read_sysreg(pmcr_el0);
}

static inline void write_pmselr(u32 val)
{
	write_sysreg(val, pmselr_el0);
}

static inline void write_pmccntr(u64 val)
{
	write_sysreg(val, pmccntr_el0);
}

static inline u64 read_pmccntr(void)
{
	return read_sysreg(pmccntr_el0);
}

static inline void write_pmxevcntr(u32 val)
{
	write_sysreg(val, pmxevcntr_el0);
}

static inline u32 read_pmxevcntr(void)
{
	return read_sysreg(pmxevcntr_el0);
}

static inline void write_pmxevtyper(u32 val)
{
	write_sysreg(val, pmxevtyper_el0);
}

static inline void write_pmcntenset(u32 val)
{
	write_sysreg(val, pmcntenset_el0);
}

static inline void write_pmcntenclr(u32 val)
{
	write_sysreg(val, pmcntenclr_el0);
}

static inline void write_pmintenset(u32 val)
{
	write_sysreg(val, pmintenset_el1);
}

static inline void write_pmintenclr(u32 val)
{
	write_sysreg(val, pmintenclr_el1);
}

static inline void write_pmccfiltr(u32 val)
{
	write_sysreg(val, pmccfiltr_el0);
}

static inline void write_pmovsclr(u32 val)
{
	write_sysreg(val, pmovsclr_el0);
}

static inline u32 read_pmovsclr(void)
{
	return read_sysreg(pmovsclr_el0);
}

static inline void write_pmuserenr(u32 val)
{
	write_sysreg(val, pmuserenr_el0);
}

static inline u32 read_pmceid0(void)
{
	return read_sysreg(pmceid0_el0);
}

static inline u32 read_pmceid1(void)
{
	return read_sysreg(pmceid1_el0);
}

#endif
