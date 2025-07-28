// SPDX-License-Identifier: GPL-2.0-only
/*
 * CPU-agnostic ARM page table allocator.
 *
 * Copyright (C) 2022 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */
#include <linux/sizes.h>
#include <linux/types.h>

#include "io-pgtable-arm.h"

/*
 * Check if concatenated PGDs are mandatory according to Arm DDI0487 (K.a)
 * 1) R_DXBSH: For 16KB, and 48-bit input size, use level 1 instead of 0.
 * 2) R_SRKBC: After de-ciphering the table for PA size and valid initial lookup
 *   a) 40 bits PA size with 4K: use level 1 instead of level 0 (2 tables for ias = oas)
 *   b) 40 bits PA size with 16K: use level 2 instead of level 1 (16 tables for ias = oas)
 *   c) 42 bits PA size with 4K: use level 1 instead of level 0 (8 tables for ias = oas)
 *   d) 48 bits PA size with 16K: use level 1 instead of level 0 (2 tables for ias = oas)
 */
static inline bool arm_lpae_concat_mandatory(struct io_pgtable_cfg *cfg,
					     struct arm_lpae_io_pgtable *data)
{
	unsigned int ias = cfg->ias;
	unsigned int oas = cfg->oas;

	/* Covers 1 and 2.d */
	if ((ARM_LPAE_GRANULE(data) == SZ_16K) && (data->start_level == 0))
		return (oas == 48) || (ias == 48);

	/* Covers 2.a and 2.c */
	if ((ARM_LPAE_GRANULE(data) == SZ_4K) && (data->start_level == 0))
		return (oas == 40) || (oas == 42);

	/* Case 2.b */
	return (ARM_LPAE_GRANULE(data) == SZ_16K) &&
	       (data->start_level == 1) && (oas == 40);
}

static void arm_lpae_restrict_pgsizes(struct io_pgtable_cfg *cfg)
{
	unsigned long granule, page_sizes;
	unsigned int max_addr_bits = 48;

	/*
	 * We need to restrict the supported page sizes to match the
	 * translation regime for a particular granule. Aim to match
	 * the CPU page size if possible, otherwise prefer smaller sizes.
	 * While we're at it, restrict the block sizes to match the
	 * chosen granule.
	 */
	if (cfg->pgsize_bitmap & PAGE_SIZE)
		granule = PAGE_SIZE;
	else if (cfg->pgsize_bitmap & ~PAGE_MASK)
		granule = 1UL << __fls(cfg->pgsize_bitmap & ~PAGE_MASK);
	else if (cfg->pgsize_bitmap & PAGE_MASK)
		granule = 1UL << __ffs(cfg->pgsize_bitmap & PAGE_MASK);
	else
		granule = 0;

	switch (granule) {
	case SZ_4K:
		page_sizes = (SZ_4K | SZ_2M | SZ_1G);
		break;
	case SZ_16K:
		page_sizes = (SZ_16K | SZ_32M);
		break;
	case SZ_64K:
		max_addr_bits = 52;
		page_sizes = (SZ_64K | SZ_512M);
		if (cfg->oas > 48)
			page_sizes |= 1ULL << 42; /* 4TB */
		break;
	default:
		page_sizes = 0;
	}

	cfg->pgsize_bitmap &= page_sizes;
	cfg->ias = min(cfg->ias, max_addr_bits);
	cfg->oas = min(cfg->oas, max_addr_bits);
}

int arm_lpae_init_pgtable(struct io_pgtable_cfg *cfg,
			  struct arm_lpae_io_pgtable *data)
{
	int levels, va_bits, pg_shift;

	arm_lpae_restrict_pgsizes(cfg);

	if (!(cfg->pgsize_bitmap & (SZ_4K | SZ_16K | SZ_64K)))
		return -EINVAL;

	if (cfg->ias > ARM_LPAE_MAX_ADDR_BITS)
		return E2BIG;

	if (cfg->oas > ARM_LPAE_MAX_ADDR_BITS)
		return -E2BIG;

	pg_shift = __ffs(cfg->pgsize_bitmap);
	data->bits_per_level = pg_shift - ilog2(sizeof(arm_lpae_iopte));

	va_bits = cfg->ias - pg_shift;
	levels = DIV_ROUND_UP(va_bits, data->bits_per_level);
	data->start_level = ARM_LPAE_MAX_LEVELS - levels;

	/* Calculate the actual size of our pgd (without concatenation) */
	data->pgd_bits = va_bits - (data->bits_per_level * (levels - 1));
	return 0;
}

int arm_lpae_init_pgtable_s1(struct io_pgtable_cfg *cfg,
			     struct arm_lpae_io_pgtable *data,
			     void *cookie)
{
	u64 reg;
	int ret;
	typeof(&cfg->arm_lpae_s1_cfg.tcr) tcr = &cfg->arm_lpae_s1_cfg.tcr;
	bool tg1;

	if (cfg->quirks & ~(IO_PGTABLE_QUIRK_ARM_NS |
			    IO_PGTABLE_QUIRK_ARM_TTBR1 |
			    IO_PGTABLE_QUIRK_ARM_OUTER_WBWA |
			    IO_PGTABLE_QUIRK_ARM_HD |
			    IO_PGTABLE_QUIRK_NO_WARN))
		return -EINVAL;

	ret = arm_lpae_init_pgtable(cfg, data);
	if (ret)
		return ret;

	/* TCR */
	if (cfg->coherent_walk) {
		tcr->sh = ARM_LPAE_TCR_SH_IS;
		tcr->irgn = ARM_LPAE_TCR_RGN_WBWA;
		tcr->orgn = ARM_LPAE_TCR_RGN_WBWA;
		if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_OUTER_WBWA)
			return -EINVAL;
	} else {
		tcr->sh = ARM_LPAE_TCR_SH_OS;
		tcr->irgn = ARM_LPAE_TCR_RGN_NC;
		if (!(cfg->quirks & IO_PGTABLE_QUIRK_ARM_OUTER_WBWA))
			tcr->orgn = ARM_LPAE_TCR_RGN_NC;
		else
			tcr->orgn = ARM_LPAE_TCR_RGN_WBWA;
	}

	tg1 = cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1;
	switch (ARM_LPAE_GRANULE(data)) {
	case SZ_4K:
		tcr->tg = tg1 ? ARM_LPAE_TCR_TG1_4K : ARM_LPAE_TCR_TG0_4K;
		break;
	case SZ_16K:
		tcr->tg = tg1 ? ARM_LPAE_TCR_TG1_16K : ARM_LPAE_TCR_TG0_16K;
		break;
	case SZ_64K:
		tcr->tg = tg1 ? ARM_LPAE_TCR_TG1_64K : ARM_LPAE_TCR_TG0_64K;
		break;
	}

	switch (cfg->oas) {
	case 32:
		tcr->ips = ARM_LPAE_TCR_PS_32_BIT;
		break;
	case 36:
		tcr->ips = ARM_LPAE_TCR_PS_36_BIT;
		break;
	case 40:
		tcr->ips = ARM_LPAE_TCR_PS_40_BIT;
		break;
	case 42:
		tcr->ips = ARM_LPAE_TCR_PS_42_BIT;
		break;
	case 44:
		tcr->ips = ARM_LPAE_TCR_PS_44_BIT;
		break;
	case 48:
		tcr->ips = ARM_LPAE_TCR_PS_48_BIT;
		break;
	case 52:
		tcr->ips = ARM_LPAE_TCR_PS_52_BIT;
		break;
	default:
		return -EINVAL;
	}

	tcr->tsz = 64ULL - cfg->ias;

	/* MAIRs */
	reg = (ARM_LPAE_MAIR_ATTR_NC
	       << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_NC)) |
	      (ARM_LPAE_MAIR_ATTR_WBRWA
	       << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_CACHE)) |
	      (ARM_LPAE_MAIR_ATTR_DEVICE
	       << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_DEV)) |
	      (ARM_LPAE_MAIR_ATTR_INC_OWBRWA
	       << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_INC_OCACHE));

	cfg->arm_lpae_s1_cfg.mair = reg;

	/* Looking good; allocate a pgd */
	data->pgd = __arm_lpae_alloc_pages(ARM_LPAE_PGD_SIZE(data),
					   GFP_KERNEL, cfg, cookie);
	if (!data->pgd)
		return -ENOMEM;

	/* Ensure the empty pgd is visible before any actual TTBR write */
	wmb();

	/* TTBR */
	cfg->arm_lpae_s1_cfg.ttbr = __arm_lpae_virt_to_phys(data->pgd);
	return 0;
}

int arm_lpae_init_pgtable_s2(struct io_pgtable_cfg *cfg,
			     struct arm_lpae_io_pgtable *data,
			     void *cookie)
{
	u64 sl;
	int ret;
	typeof(&cfg->arm_lpae_s2_cfg.vtcr) vtcr = &cfg->arm_lpae_s2_cfg.vtcr;

	if (cfg->quirks & ~(IO_PGTABLE_QUIRK_ARM_S2FWB |
			    IO_PGTABLE_QUIRK_NO_WARN))
		return -EINVAL;

	ret = arm_lpae_init_pgtable(cfg, data);
	if (ret)
		return ret;

	if (arm_lpae_concat_mandatory(cfg, data)) {
		if (WARN_ON((ARM_LPAE_PGD_SIZE(data) / sizeof(arm_lpae_iopte)) >
			    ARM_LPAE_S2_MAX_CONCAT_PAGES))
			return -EINVAL;
		data->pgd_bits += data->bits_per_level;
		data->start_level++;
	}

	/* VTCR */
	if (cfg->coherent_walk) {
		vtcr->sh = ARM_LPAE_TCR_SH_IS;
		vtcr->irgn = ARM_LPAE_TCR_RGN_WBWA;
		vtcr->orgn = ARM_LPAE_TCR_RGN_WBWA;
	} else {
		vtcr->sh = ARM_LPAE_TCR_SH_OS;
		vtcr->irgn = ARM_LPAE_TCR_RGN_NC;
		vtcr->orgn = ARM_LPAE_TCR_RGN_NC;
	}

	sl = data->start_level;

	switch (ARM_LPAE_GRANULE(data)) {
	case SZ_4K:
		vtcr->tg = ARM_LPAE_TCR_TG0_4K;
		sl++; /* SL0 format is different for 4K granule size */
		break;
	case SZ_16K:
		vtcr->tg = ARM_LPAE_TCR_TG0_16K;
		break;
	case SZ_64K:
		vtcr->tg = ARM_LPAE_TCR_TG0_64K;
		break;
	}

	switch (cfg->oas) {
	case 32:
		vtcr->ps = ARM_LPAE_TCR_PS_32_BIT;
		break;
	case 36:
		vtcr->ps = ARM_LPAE_TCR_PS_36_BIT;
		break;
	case 40:
		vtcr->ps = ARM_LPAE_TCR_PS_40_BIT;
		break;
	case 42:
		vtcr->ps = ARM_LPAE_TCR_PS_42_BIT;
		break;
	case 44:
		vtcr->ps = ARM_LPAE_TCR_PS_44_BIT;
		break;
	case 48:
		vtcr->ps = ARM_LPAE_TCR_PS_48_BIT;
		break;
	case 52:
		vtcr->ps = ARM_LPAE_TCR_PS_52_BIT;
		break;
	default:
		return -EINVAL;
	}

	vtcr->tsz = 64ULL - cfg->ias;
	vtcr->sl = ~sl & ARM_LPAE_VTCR_SL0_MASK;

	/* Allocate pgd pages */
	data->pgd = __arm_lpae_alloc_pages(PAGE_ALIGN(ARM_LPAE_PGD_SIZE(data)),
					   GFP_KERNEL, cfg, cookie);
	if (!data->pgd)
		return -ENOMEM;

	/* Ensure the empty pgd is visible before any actual TTBR write */
	wmb();

	/* VTTBR */
	cfg->arm_lpae_s2_cfg.vttbr = __arm_lpae_virt_to_phys(data->pgd);
	return 0;
}

/*
 * Convert an index returned by ARM_LPAE_PGD_IDX(), which can point into
 * a concatenated PGD, into the maximum number of entries that can be
 * mapped in the same table page.
 */
static inline int arm_lpae_max_entries(int i, struct arm_lpae_io_pgtable *data)
{
	int ptes_per_table = ARM_LPAE_PTES_PER_TABLE(data);

	return ptes_per_table - (i & (ptes_per_table - 1));
}

static void __arm_lpae_clear_pte(arm_lpae_iopte *ptep, struct io_pgtable_cfg *cfg, int num_entries)
{
	for (int i = 0; i < num_entries; i++)
		ptep[i] = 0;

	if (!cfg->coherent_walk && num_entries)
		__arm_lpae_sync_pte(ptep, num_entries, cfg);
}

static size_t __arm_lpae_unmap(struct arm_lpae_io_pgtable *data,
			       struct iommu_iotlb_gather *gather,
			       unsigned long iova, size_t size, size_t pgcount,
			       int lvl, arm_lpae_iopte *ptep);

static void __arm_lpae_init_pte(struct arm_lpae_io_pgtable *data,
				phys_addr_t paddr, arm_lpae_iopte prot,
				int lvl, int num_entries, arm_lpae_iopte *ptep)
{
	arm_lpae_iopte pte = prot;
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	size_t sz = ARM_LPAE_BLOCK_SIZE(lvl, data);
	int i;

	if (data->iop.fmt != ARM_MALI_LPAE && lvl == ARM_LPAE_MAX_LEVELS - 1)
		pte |= ARM_LPAE_PTE_TYPE_PAGE;
	else
		pte |= ARM_LPAE_PTE_TYPE_BLOCK;

	for (i = 0; i < num_entries; i++)
		ptep[i] = pte | paddr_to_iopte(paddr + i * sz, data);

	if (!cfg->coherent_walk)
		__arm_lpae_sync_pte(ptep, num_entries, cfg);
}

static int arm_lpae_init_pte(struct arm_lpae_io_pgtable *data,
			     unsigned long iova, phys_addr_t paddr,
			     arm_lpae_iopte prot, int lvl, int num_entries,
			     arm_lpae_iopte *ptep)
{
	int i;

	for (i = 0; i < num_entries; i++)
		if (iopte_leaf(ptep[i], lvl, data->iop.fmt)) {
			/* We require an unmap first */
			WARN_ON(!(data->iop.cfg.quirks & IO_PGTABLE_QUIRK_NO_WARN));
			return -EEXIST;
		} else if (iopte_type(ptep[i]) == ARM_LPAE_PTE_TYPE_TABLE) {
			/*
			 * We need to unmap and free the old table before
			 * overwriting it with a block entry.
			 */
			arm_lpae_iopte *tblp;
			size_t sz = ARM_LPAE_BLOCK_SIZE(lvl, data);

			tblp = ptep - ARM_LPAE_LVL_IDX(iova, lvl, data);
			if (__arm_lpae_unmap(data, NULL, iova + i * sz, sz, 1,
					     lvl, tblp) != sz) {
				WARN_ON(1);
				return -EINVAL;
			}
		}

	__arm_lpae_init_pte(data, paddr, prot, lvl, num_entries, ptep);
	return 0;
}

static arm_lpae_iopte arm_lpae_install_table(arm_lpae_iopte *table,
					     arm_lpae_iopte *ptep,
					     arm_lpae_iopte curr,
					     struct arm_lpae_io_pgtable *data)
{
	arm_lpae_iopte old, new;
	struct io_pgtable_cfg *cfg = &data->iop.cfg;

	new = paddr_to_iopte(__arm_lpae_virt_to_phys(table), data) |
			     ARM_LPAE_PTE_TYPE_TABLE;
	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_NS)
		new |= ARM_LPAE_PTE_NSTABLE;

	/*
	 * Ensure the table itself is visible before its PTE can be.
	 * Whilst we could get away with cmpxchg64_release below, this
	 * doesn't have any ordering semantics when !CONFIG_SMP.
	 */
	dma_wmb();

	old = cmpxchg64_relaxed(ptep, curr, new);

	if (cfg->coherent_walk || (old & ARM_LPAE_PTE_SW_SYNC))
		return old;

	/* Even if it's not ours, there's no point waiting; just kick it */
	__arm_lpae_sync_pte(ptep, 1, cfg);
	if (old == curr)
		WRITE_ONCE(*ptep, new | ARM_LPAE_PTE_SW_SYNC);

	return old;
}

static int __arm_lpae_map(struct arm_lpae_io_pgtable *data, unsigned long iova,
			  phys_addr_t paddr, size_t size, size_t pgcount,
			  arm_lpae_iopte prot, int lvl, arm_lpae_iopte *ptep,
			  gfp_t gfp, size_t *mapped)
{
	arm_lpae_iopte *cptep, pte;
	size_t block_size = ARM_LPAE_BLOCK_SIZE(lvl, data);
	size_t tblsz = ARM_LPAE_GRANULE(data);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	int ret = 0, num_entries, max_entries, map_idx_start;

	/* Find our entry at the current level */
	map_idx_start = ARM_LPAE_LVL_IDX(iova, lvl, data);
	ptep += map_idx_start;

	/* If we can install a leaf entry at this level, then do so */
	if (size == block_size) {
		max_entries = arm_lpae_max_entries(map_idx_start, data);
		num_entries = min_t(int, pgcount, max_entries);
		ret = arm_lpae_init_pte(data, iova, paddr, prot, lvl, num_entries, ptep);
		if (!ret)
			*mapped += num_entries * size;

		return ret;
	}

	/* We can't allocate tables at the final level */
	if (WARN_ON(lvl >= ARM_LPAE_MAX_LEVELS - 1))
		return -EINVAL;

	/* Grab a pointer to the next level */
	pte = READ_ONCE(*ptep);
	if (!pte) {
		cptep = __arm_lpae_alloc_pages(tblsz, gfp, cfg, data->iop.cookie);
		if (!cptep)
			return -ENOMEM;

		pte = arm_lpae_install_table(cptep, ptep, 0, data);
		if (pte)
			__arm_lpae_free_pages(cptep, tblsz, cfg, data->iop.cookie);
	} else if (!cfg->coherent_walk && !(pte & ARM_LPAE_PTE_SW_SYNC)) {
		__arm_lpae_sync_pte(ptep, 1, cfg);
	}

	if (pte && !iopte_leaf(pte, lvl, data->iop.fmt)) {
		cptep = iopte_deref(pte, data);
	} else if (pte) {
		/* We require an unmap first */
		WARN_ON(!(cfg->quirks & IO_PGTABLE_QUIRK_NO_WARN));
		return -EEXIST;
	}

	/* Rinse, repeat */
	return __arm_lpae_map(data, iova, paddr, size, pgcount, prot, lvl + 1,
			      cptep, gfp, mapped);
}

static arm_lpae_iopte arm_lpae_prot_to_pte(struct arm_lpae_io_pgtable *data,
					   int prot)
{
	arm_lpae_iopte pte;

	if (data->iop.fmt == ARM_64_LPAE_S1 ||
	    data->iop.fmt == ARM_32_LPAE_S1) {
		pte = ARM_LPAE_PTE_nG;
		if (!(prot & IOMMU_WRITE) && (prot & IOMMU_READ))
			pte |= ARM_LPAE_PTE_AP_RDONLY;
		else if (data->iop.cfg.quirks & IO_PGTABLE_QUIRK_ARM_HD)
			pte |= ARM_LPAE_PTE_DBM;
		if (!(prot & IOMMU_PRIV))
			pte |= ARM_LPAE_PTE_AP_UNPRIV;
	} else {
		pte = ARM_LPAE_PTE_HAP_FAULT;
		if (prot & IOMMU_READ)
			pte |= ARM_LPAE_PTE_HAP_READ;
		if (prot & IOMMU_WRITE)
			pte |= ARM_LPAE_PTE_HAP_WRITE;
	}

	/*
	 * Note that this logic is structured to accommodate Mali LPAE
	 * having stage-1-like attributes but stage-2-like permissions.
	 */
	if (data->iop.fmt == ARM_64_LPAE_S2 ||
	    data->iop.fmt == ARM_32_LPAE_S2) {
		if (prot & IOMMU_MMIO) {
			pte |= ARM_LPAE_PTE_MEMATTR_DEV;
		} else if (prot & IOMMU_CACHE) {
			if (data->iop.cfg.quirks & IO_PGTABLE_QUIRK_ARM_S2FWB)
				pte |= ARM_LPAE_PTE_MEMATTR_FWB_WB;
			else
				pte |= ARM_LPAE_PTE_MEMATTR_OIWB;
		} else {
			pte |= ARM_LPAE_PTE_MEMATTR_NC;
		}
	} else {
		if (prot & IOMMU_MMIO)
			pte |= (ARM_LPAE_MAIR_ATTR_IDX_DEV
				<< ARM_LPAE_PTE_ATTRINDX_SHIFT);
		else if (prot & IOMMU_CACHE)
			pte |= (ARM_LPAE_MAIR_ATTR_IDX_CACHE
				<< ARM_LPAE_PTE_ATTRINDX_SHIFT);
	}

	/*
	 * Also Mali has its own notions of shareability wherein its Inner
	 * domain covers the cores within the GPU, and its Outer domain is
	 * "outside the GPU" (i.e. either the Inner or System domain in CPU
	 * terms, depending on coherency).
	 */
	if (prot & IOMMU_CACHE && data->iop.fmt != ARM_MALI_LPAE)
		pte |= ARM_LPAE_PTE_SH_IS;
	else
		pte |= ARM_LPAE_PTE_SH_OS;

	if (prot & IOMMU_NOEXEC)
		pte |= ARM_LPAE_PTE_XN;

	if (data->iop.cfg.quirks & IO_PGTABLE_QUIRK_ARM_NS)
		pte |= ARM_LPAE_PTE_NS;

	if (data->iop.fmt != ARM_MALI_LPAE)
		pte |= ARM_LPAE_PTE_AF;

	return pte;
}

int arm_lpae_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
		       phys_addr_t paddr, size_t pgsize, size_t pgcount,
		       int iommu_prot, gfp_t gfp, size_t *mapped)
{
	struct arm_lpae_io_pgtable *data = io_pgtable_ops_to_data(ops);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	arm_lpae_iopte *ptep = data->pgd;
	int ret, lvl = data->start_level;
	arm_lpae_iopte prot;
	long iaext = (s64)iova >> cfg->ias;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize))
		return -EINVAL;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext || paddr >> cfg->oas))
		return -ERANGE;

	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return -EINVAL;

	prot = arm_lpae_prot_to_pte(data, iommu_prot);
	ret = __arm_lpae_map(data, iova, paddr, pgsize, pgcount, prot, lvl,
			     ptep, gfp, mapped);
	/*
	 * Synchronise all PTE updates for the new mapping before there's
	 * a chance for anything to kick off a table walk for the new iova.
	 */
	wmb();

	return ret;
}

void __arm_lpae_free_pgtable(struct arm_lpae_io_pgtable *data, int lvl,
			     arm_lpae_iopte *ptep)
{
	arm_lpae_iopte *start, *end;
	unsigned long table_size;

	if (lvl == data->start_level)
		table_size = ARM_LPAE_PGD_SIZE(data);
	else
		table_size = ARM_LPAE_GRANULE(data);

	start = ptep;

	/* Only leaf entries at the last level */
	if (lvl == ARM_LPAE_MAX_LEVELS - 1)
		end = ptep;
	else
		end = (void *)ptep + table_size;

	while (ptep != end) {
		arm_lpae_iopte pte = *ptep++;

		if (!pte || iopte_leaf(pte, lvl, data->iop.fmt))
			continue;

		__arm_lpae_free_pgtable(data, lvl + 1, iopte_deref(pte, data));
	}

	__arm_lpae_free_pages(start, table_size, &data->iop.cfg, data->iop.cookie);
}

static size_t __arm_lpae_unmap(struct arm_lpae_io_pgtable *data,
			       struct iommu_iotlb_gather *gather,
			       unsigned long iova, size_t size, size_t pgcount,
			       int lvl, arm_lpae_iopte *ptep)
{
	arm_lpae_iopte pte;
	struct io_pgtable *iop = &data->iop;
	int i = 0, num_entries, max_entries, unmap_idx_start;

	/* Something went horribly wrong and we ran out of page table */
	if (WARN_ON(lvl == ARM_LPAE_MAX_LEVELS))
		return 0;

	unmap_idx_start = ARM_LPAE_LVL_IDX(iova, lvl, data);
	ptep += unmap_idx_start;
	pte = READ_ONCE(*ptep);
	if (!pte) {
		WARN_ON(!(data->iop.cfg.quirks & IO_PGTABLE_QUIRK_NO_WARN));
		return -ENOENT;
	}

	/* If the size matches this level, we're in the right place */
	if (size == ARM_LPAE_BLOCK_SIZE(lvl, data)) {
		max_entries = arm_lpae_max_entries(unmap_idx_start, data);
		num_entries = min_t(int, pgcount, max_entries);

		/* Find and handle non-leaf entries */
		for (i = 0; i < num_entries; i++) {
			pte = READ_ONCE(ptep[i]);
			if (!pte) {
				WARN_ON(!(data->iop.cfg.quirks & IO_PGTABLE_QUIRK_NO_WARN));
				break;
			}

			if (!iopte_leaf(pte, lvl, iop->fmt)) {
				__arm_lpae_clear_pte(&ptep[i], &iop->cfg, 1);

				/* Also flush any partial walks */
				io_pgtable_tlb_flush_walk(iop, iova + i * size, size,
							  ARM_LPAE_GRANULE(data));
				__arm_lpae_free_pgtable(data, lvl + 1, iopte_deref(pte, data));
			}
		}

		/* Clear the remaining entries */
		__arm_lpae_clear_pte(ptep, &iop->cfg, i);

		if (gather && !iommu_iotlb_gather_queued(gather))
			for (int j = 0; j < i; j++)
				io_pgtable_tlb_add_page(iop, gather, iova + j * size, size);

		return i * size;
	} else if (iopte_leaf(pte, lvl, iop->fmt)) {
		arm_lpae_split_blk();
		return 0;
	}

	/* Keep on walkin' */
	ptep = iopte_deref(pte, data);
	return __arm_lpae_unmap(data, gather, iova, size, pgcount, lvl + 1, ptep);
}

size_t arm_lpae_unmap_pages(struct io_pgtable_ops *ops, unsigned long iova,
			    size_t pgsize, size_t pgcount,
			    struct iommu_iotlb_gather *gather)
{
	struct arm_lpae_io_pgtable *data = io_pgtable_ops_to_data(ops);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	arm_lpae_iopte *ptep = data->pgd;
	long iaext = (s64)iova >> cfg->ias;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize || !pgcount))
		return 0;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext))
		return 0;

	return __arm_lpae_unmap(data, gather, iova, pgsize, pgcount,
				data->start_level, ptep);
}
