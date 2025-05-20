// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#include <asm/kvm_pgtable.h>

static unsigned long rmm_feat_reg0;

#define RMM_PAGE_SHIFT		12
#define RMM_PAGE_SIZE		BIT(RMM_PAGE_SHIFT)

#define RMM_RTT_BLOCK_LEVEL	2
#define RMM_RTT_MAX_LEVEL	3

/* See ARM64_HW_PGTABLE_LEVEL_SHIFT() */
#define RMM_RTT_LEVEL_SHIFT(l)	\
	((RMM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define RMM_L2_BLOCK_SIZE	BIT(RMM_RTT_LEVEL_SHIFT(2))

static inline unsigned long rme_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return RMM_PAGE_SIZE;

	return (1UL << RMM_RTT_LEVEL_SHIFT(level));
}

static bool rme_has_feature(unsigned long feature)
{
	return !!u64_get_bits(rmm_feat_reg0, feature);
}

static int rmi_check_version(void)
{
	struct arm_smccc_res res;
	unsigned short version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);

	arm_smccc_1_1_invoke(SMC_RMI_VERSION, host_version, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		unsigned short high_version_major, high_version_minor;

		high_version_major = RMI_ABI_VERSION_GET_MAJOR(res.a2);
		high_version_minor = RMI_ABI_VERSION_GET_MINOR(res.a2);

		kvm_err("Unsupported RMI ABI (v%d.%d - v%d.%d) we want v%d.%d\n",
			version_major, version_minor,
			high_version_major, high_version_minor,
			RMI_ABI_MAJOR_VERSION,
			RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	kvm_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

u32 kvm_realm_ipa_limit(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_S2SZ);
}

static int get_start_level(struct realm *realm)
{
	return 4 - ((realm->ia_bits - 8) / (RMM_PAGE_SHIFT - 3));
}

static void free_delegated_granule(phys_addr_t phys)
{
	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Undelegate failed: leak the page */
		return;
	}

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);

	free_page((unsigned long)phys_to_virt(phys));
}

/* Calculate the number of s2 root rtts needed */
static int realm_num_root_rtts(struct realm *realm)
{
	unsigned int ipa_bits = realm->ia_bits;
	unsigned int levels = 3 - get_start_level(realm);
	unsigned int sl_ipa_bits = (levels + 1) * (RMM_PAGE_SHIFT - 3) +
				   RMM_PAGE_SHIFT;

	if (sl_ipa_bits >= ipa_bits)
		return 1;

	return 1 << (ipa_bits - sl_ipa_bits);
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params = realm->params;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	int i, r;
	int rtt_num_start;

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	rtt_num_start = realm_num_root_rtts(realm);

	if (WARN_ON(realm->rd || !realm->params))
		return -EEXIST;

	if (pgd_size / RMM_PAGE_SIZE < rtt_num_start)
		return -EINVAL;

	rd = (void *)__get_free_page(GFP_KERNEL);
	if (!rd)
		return -ENOMEM;

	rd_phys = virt_to_phys(rd);
	if (rmi_granule_delegate(rd_phys)) {
		r = -ENXIO;
		goto free_rd;
	}

	for (i = 0; i < pgd_size; i += RMM_PAGE_SIZE) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (rmi_granule_delegate(pgd_phys)) {
			r = -ENXIO;
			goto out_undelegate_tables;
		}
	}

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = rtt_num_start;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->vmid = realm->vmid;

	params_phys = virt_to_phys(params);

	if (rmi_realm_create(rd_phys, params_phys)) {
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	if (WARN_ON(rmi_rec_aux_count(rd_phys, &realm->num_aux))) {
		WARN_ON(rmi_realm_destroy(rd_phys));
		goto out_undelegate_tables;
	}

	realm->rd = rd;

	return 0;

out_undelegate_tables:
	while (i > 0) {
		i -= RMM_PAGE_SIZE;

		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (WARN_ON(rmi_granule_undelegate(pgd_phys))) {
			/* Leak the pages if they cannot be returned */
			kvm->arch.mmu.pgt = NULL;
			break;
		}
	}
	if (WARN_ON(rmi_granule_undelegate(rd_phys))) {
		/* Leak the page if it isn't returned */
		return r;
	}
free_rd:
	free_page((unsigned long)rd);
	return r;
}

static int realm_rtt_destroy(struct realm *realm, unsigned long addr,
			     int level, phys_addr_t *rtt_granule,
			     unsigned long *next_addr)
{
	unsigned long out_rtt;
	int ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);

	*rtt_granule = out_rtt;

	return ret;
}

static int realm_tear_down_rtt_level(struct realm *realm, int level,
				     unsigned long start, unsigned long end)
{
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return -EINVAL;

	map_size = rme_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		if (next_addr > end || align_addr != addr) {
			/*
			 * The target range is smaller than what this level
			 * covers, recurse deeper.
			 */
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							min(next_addr, end));
			if (ret)
				return ret;
			continue;
		}

		ret = realm_rtt_destroy(realm, addr, level,
					&rtt_granule, &next_addr);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_delegated_granule(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ON(RMI_RETURN_INDEX(ret) != level))
				return -EBUSY;
			if (WARN_ON(level == RMM_RTT_MAX_LEVEL))
				return -EBUSY;

			/*
			 * The table has active entries in it, recurse deeper
			 * and tear down the RTTs.
			 */
			next_addr = ALIGN(addr + 1, map_size);
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							next_addr);
			if (ret)
				return ret;
			/*
			 * Now that the child RTTs are destroyed,
			 * retry at this level.
			 */
			next_addr = addr;
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_range(struct realm *realm,
				     unsigned long start, unsigned long end)
{
	return realm_tear_down_rtt_level(realm, get_start_level(realm) + 1,
					 start, end);
}

void kvm_realm_destroy_rtts(struct kvm *kvm, u32 ia_bits)
{
	struct realm *realm = &kvm->arch.realm;

	WARN_ON(realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits)));
}

/* Protects access to rme_vmid_bitmap */
static DEFINE_SPINLOCK(rme_vmid_lock);
static unsigned long *rme_vmid_bitmap;

static int rme_vmid_init(void)
{
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	rme_vmid_bitmap = bitmap_zalloc(vmid_count, GFP_KERNEL);
	if (!rme_vmid_bitmap) {
		kvm_err("%s: Couldn't allocate rme vmid bitmap\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static int rme_vmid_reserve(void)
{
	int ret;
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	spin_lock(&rme_vmid_lock);
	ret = bitmap_find_free_region(rme_vmid_bitmap, vmid_count, 0);
	spin_unlock(&rme_vmid_lock);

	return ret;
}

static void rme_vmid_release(unsigned int vmid)
{
	spin_lock(&rme_vmid_lock);
	bitmap_release_region(rme_vmid_bitmap, vmid, 0);
	spin_unlock(&rme_vmid_lock);
}

static int kvm_create_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	int ret;

	if (!kvm_is_realm(kvm))
		return -EINVAL;
	if (kvm_realm_is_created(kvm))
		return -EEXIST;

	ret = rme_vmid_reserve();
	if (ret < 0)
		return ret;
	realm->vmid = ret;

	ret = realm_create_rd(kvm);
	if (ret) {
		rme_vmid_release(realm->vmid);
		return ret;
	}

	WRITE_ONCE(realm->state, REALM_STATE_NEW);

	/* The realm is up, free the parameters.  */
	free_page((unsigned long)realm->params);
	realm->params = NULL;

	return 0;
}

static int config_realm_hash_algo(struct realm *realm,
				  struct arm_rme_config *cfg)
{
	switch (cfg->hash_algo) {
	case ARM_RME_CONFIG_MEASUREMENT_ALGO_SHA256:
		if (!rme_has_feature(RMI_FEATURE_REGISTER_0_HASH_SHA_256))
			return -EINVAL;
		break;
	case ARM_RME_CONFIG_MEASUREMENT_ALGO_SHA512:
		if (!rme_has_feature(RMI_FEATURE_REGISTER_0_HASH_SHA_512))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	realm->params->hash_algo = cfg->hash_algo;
	return 0;
}

static int kvm_rme_config_realm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct arm_rme_config cfg;
	struct realm *realm = &kvm->arch.realm;
	int r = 0;

	if (kvm_realm_is_created(kvm))
		return -EBUSY;

	if (copy_from_user(&cfg, (void __user *)cap->args[1], sizeof(cfg)))
		return -EFAULT;

	switch (cfg.cfg) {
	case ARM_RME_CONFIG_RPV:
		memcpy(&realm->params->rpv, &cfg.rpv, sizeof(cfg.rpv));
		break;
	case ARM_RME_CONFIG_HASH_ALGO:
		r = config_realm_hash_algo(realm, &cfg);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r = 0;

	if (!kvm_is_realm(kvm))
		return -EINVAL;

	switch (cap->args[0]) {
	case KVM_CAP_ARM_RME_CONFIG_REALM:
		r = kvm_rme_config_realm(kvm, cap);
		break;
	case KVM_CAP_ARM_RME_CREATE_REALM:
		r = kvm_create_realm(kvm);
		break;
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	int i;

	if (realm->params) {
		free_page((unsigned long)realm->params);
		realm->params = NULL;
	}

	if (!kvm_realm_is_created(kvm))
		return;

	WRITE_ONCE(realm->state, REALM_STATE_DYING);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		if (WARN_ON(rmi_realm_destroy(rd_phys)))
			return;
		free_delegated_granule(rd_phys);
		realm->rd = NULL;
	}

	rme_vmid_release(realm->vmid);

	for (i = 0; i < pgd_size; i += RMM_PAGE_SIZE) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (WARN_ON(rmi_granule_undelegate(pgd_phys)))
			return;
	}

	WRITE_ONCE(realm->state, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

int kvm_init_realm_vm(struct kvm *kvm)
{
	kvm->arch.realm.params = (void *)get_zeroed_page(GFP_KERNEL);

	if (!kvm->arch.realm.params)
		return -ENOMEM;
	return 0;
}

void kvm_init_rme(void)
{
	if (PAGE_SIZE != SZ_4K)
		/* Only 4k page size on the host is supported */
		return;

	if (rmi_check_version())
		/* Continue without realm support */
		return;

	if (WARN_ON(rmi_features(0, &rmm_feat_reg0)))
		return;

	if (rme_vmid_init())
		return;

	/* Future patch will enable static branch kvm_rme_is_available */
}
