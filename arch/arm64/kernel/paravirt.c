// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2013 Citrix Systems
 *
 * Author: Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 */

#define pr_fmt(fmt) "arm-pv: " fmt

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/jump_label.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/psci.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/static_call.h>

#include <asm/hypervisor.h>
#include <asm/paravirt.h>
#include <asm/pvclock-abi.h>
#include <asm/smp_plat.h>

struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;

static u64 native_steal_clock(int cpu)
{
	return 0;
}

DEFINE_STATIC_CALL(pv_steal_clock, native_steal_clock);

struct pv_time_stolen_time_region {
	struct pvclock_vcpu_stolen_time __rcu *kaddr;
};

static DEFINE_PER_CPU(struct pv_time_stolen_time_region, stolen_time_region);

static bool steal_acc = true;
static int __init parse_no_stealacc(char *arg)
{
	steal_acc = false;
	return 0;
}

early_param("no-steal-acc", parse_no_stealacc);

/* return stolen time in ns by asking the hypervisor */
static u64 para_steal_clock(int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;
	u64 ret = 0;

	reg = per_cpu_ptr(&stolen_time_region, cpu);

	/*
	 * paravirt_steal_clock() may be called before the CPU
	 * online notification callback runs. Until the callback
	 * has run we just return zero.
	 */
	rcu_read_lock();
	kaddr = rcu_dereference(reg->kaddr);
	if (!kaddr) {
		rcu_read_unlock();
		return 0;
	}

	ret = le64_to_cpu(READ_ONCE(kaddr->stolen_time));
	rcu_read_unlock();
	return ret;
}

static int stolen_time_cpu_down_prepare(unsigned int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;

	reg = this_cpu_ptr(&stolen_time_region);
	if (!reg->kaddr)
		return 0;

	kaddr = rcu_replace_pointer(reg->kaddr, NULL, true);
	synchronize_rcu();
	memunmap(kaddr);

	return 0;
}

static int stolen_time_cpu_online(unsigned int cpu)
{
	struct pvclock_vcpu_stolen_time *kaddr = NULL;
	struct pv_time_stolen_time_region *reg;
	struct arm_smccc_res res;

	reg = this_cpu_ptr(&stolen_time_region);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_ST, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -EINVAL;

	kaddr = memremap(res.a0,
			      sizeof(struct pvclock_vcpu_stolen_time),
			      MEMREMAP_WB);

	rcu_assign_pointer(reg->kaddr, kaddr);

	if (!reg->kaddr) {
		pr_warn("Failed to map stolen time data structure\n");
		return -ENOMEM;
	}

	if (le32_to_cpu(kaddr->revision) != 0 ||
	    le32_to_cpu(kaddr->attributes) != 0) {
		pr_warn_once("Unexpected revision or attributes in stolen time data\n");
		return -ENXIO;
	}

	return 0;
}

static int __init pv_time_init_stolen_time(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"hypervisor/arm/pvtime:online",
				stolen_time_cpu_online,
				stolen_time_cpu_down_prepare);
	if (ret < 0)
		return ret;
	return 0;
}

static bool __init has_pv_steal_clock(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_TIME_FEATURES, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_FEATURES,
			     ARM_SMCCC_HV_PV_TIME_ST, &res);

	return (res.a0 == SMCCC_RET_SUCCESS);
}

void  __init pv_target_impl_cpu_init(void)
{
	int i;
	unsigned long max_cpus;
	struct arm_smccc_res res;
	const u32 funcs[] = {
		ARM_SMCCC_KVM_FUNC_DISCOVER_IMPL_VER,
		ARM_SMCCC_KVM_FUNC_DISCOVER_IMPL_CPUS,
	};

	/* Check we have already set targets */
	if (target_impl_cpu_num)
		return;

	for (i = 0; i < ARRAY_SIZE(funcs); ++i) {
		if (!kvm_arm_hyp_service_available(funcs[i]))
			return;
	}

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_DISCOVER_IMPL_VER_FUNC_ID,
			     0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return;

	if (res.a1 != ARM_SMCCC_KVM_DISCOVER_IMPL_VER_1_0 || !res.a2) {
		pr_warn("Unsupported target impl version or CPU implementations\n");
		return;
	}

	max_cpus = res.a2;
	target_impl_cpus = memblock_alloc(sizeof(*target_impl_cpus) * max_cpus,
					  __alignof__(*target_impl_cpus));
	if (!target_impl_cpus) {
		pr_warn("Not enough memory for struct target_impl_cpu\n");
		return;
	}

	for (i = 0; i < max_cpus; i++) {
		arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_DISCOVER_IMPL_CPUS_FUNC_ID,
				     i, &res);
		if (res.a0 != SMCCC_RET_SUCCESS) {
			memblock_free(target_impl_cpus,
				      sizeof(*target_impl_cpus) * max_cpus);
			target_impl_cpus = NULL;
			pr_warn("Discovering target implementation CPUs failed\n");
			return;
		}
		target_impl_cpus[i].midr = res.a1;
		target_impl_cpus[i].revidr = res.a2;
		target_impl_cpus[i].aidr = res.a3;
	};

	target_impl_cpu_num = max_cpus;
	pr_info("Number of target implementation CPUs is %d\n", target_impl_cpu_num);
}

int __init pv_time_init(void)
{
	int ret;

	if (!has_pv_steal_clock())
		return 0;

	ret = pv_time_init_stolen_time();
	if (ret)
		return ret;

	static_call_update(pv_steal_clock, para_steal_clock);

	static_key_slow_inc(&paravirt_steal_enabled);
	if (steal_acc)
		static_key_slow_inc(&paravirt_steal_rq_enabled);

	pr_info("using stolen time PV\n");

	return 0;
}
