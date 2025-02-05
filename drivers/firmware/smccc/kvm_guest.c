// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "smccc: KVM: " fmt

#include <linux/arm-smccc.h>
#include <linux/bitmap.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/string.h>

#include <uapi/linux/psci.h>

#include <asm/hypervisor.h>

static DECLARE_BITMAP(__kvm_arm_hyp_services, ARM_SMCCC_KVM_NUM_FUNCS) __ro_after_init = { };

void __init kvm_init_hyp_services(void)
{
	struct arm_smccc_res res;
	u32 val[4];

	if (arm_smccc_1_1_get_conduit() != SMCCC_CONDUIT_HVC)
		return;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, &res);
	if (res.a0 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_0 ||
	    res.a1 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_1 ||
	    res.a2 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_2 ||
	    res.a3 != ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_3)
		return;

	memset(&res, 0, sizeof(res));
	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_FEATURES_FUNC_ID, &res);

	val[0] = lower_32_bits(res.a0);
	val[1] = lower_32_bits(res.a1);
	val[2] = lower_32_bits(res.a2);
	val[3] = lower_32_bits(res.a3);

	bitmap_from_arr32(__kvm_arm_hyp_services, val, ARM_SMCCC_KVM_NUM_FUNCS);

	pr_info("hypervisor services detected (0x%08lx 0x%08lx 0x%08lx 0x%08lx)\n",
		 res.a3, res.a2, res.a1, res.a0);

	kvm_arch_init_hyp_services();
}

bool kvm_arm_hyp_service_available(u32 func_id)
{
	if (func_id >= ARM_SMCCC_KVM_NUM_FUNCS)
		return false;

	return test_bit(func_id, __kvm_arm_hyp_services);
}
EXPORT_SYMBOL_GPL(kvm_arm_hyp_service_available);

void  __init kvm_arm_target_impl_cpu_init(void)
{
	int i;
	u32 ver;
	u64 max_cpus;
	struct arm_smccc_res res;

	/* Check we have already set targets */
	if (target_impl_cpu_num)
		return;

	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_DISCOVER_IMPL_VER) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_DISCOVER_IMPL_CPUS))
		return;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_DISCOVER_IMPL_VER_FUNC_ID,
			     0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return;

	/* Version info is in lower 32 bits and is in SMMCCC_VERSION format */
	ver = lower_32_bits(res.a1);
	if (PSCI_VERSION_MAJOR(ver) != 1) {
		pr_warn("Unsupported target CPU implementation version v%d.%d\n",
			PSCI_VERSION_MAJOR(ver), PSCI_VERSION_MINOR(ver));
		return;
	}

	if (!res.a2) {
		pr_warn("No target implementation CPUs specified\n");
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
