// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support for dynamic tag storage.
 *
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/cma.h>
#include <linux/log2.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/range.h>
#include <linux/string.h>
#include <linux/xarray.h>

#include <asm/mte_tag_storage.h>

__ro_after_init DEFINE_STATIC_KEY_FALSE(tag_storage_enabled_key);

struct tag_region {
	struct range mem_range;	/* Memory associated with the tag storage, in PFNs. */
	struct range tag_range;	/* Tag storage memory, in PFNs. */
	u32 block_size_pages;	/* Tag block size, in pages. */
	phandle mem_phandle;	/* phandle for the associated memory node. */
	struct cma *cma;	/* CMA cookie */
};

#define MAX_TAG_REGIONS	32

static struct tag_region tag_regions[MAX_TAG_REGIONS];
static int num_tag_regions;

/*
 * A note on locking. Reserving tag storage takes the tag_blocks_lock mutex,
 * because alloc_contig_range() might sleep.
 *
 * Freeing tag storage takes the xa_lock spinlock with interrupts disabled
 * because pages can be freed from non-preemptible contexts, including from an
 * interrupt handler.
 *
 * Because tag storage can be freed from interrupt contexts, the xarray is
 * defined with the XA_FLAGS_LOCK_IRQ flag to disable interrupts when calling
 * xa_store(). This is done to prevent a deadlock with free_tag_storage() being
 * called from an interrupt raised before xa_store() releases the xa_lock.
 *
 * All of the above means that reserve_tag_storage() cannot run concurrently
 * with itself (no concurrent insertions), but it can run at the same time as
 * free_tag_storage(). The first thing that reserve_tag_storage() does after
 * taking the mutex is increase the refcount on all present tag storage blocks
 * with the xa_lock held, to serialize against freeing the blocks. This is an
 * optimization to avoid taking and releasing the xa_lock after each iteration
 * if the refcount operation was moved inside the loop, where it would have had
 * to be executed for each block.
 */
static DEFINE_XARRAY_FLAGS(tag_blocks_reserved, XA_FLAGS_LOCK_IRQ);
static DEFINE_MUTEX(tag_blocks_lock);

static u32 __init get_block_size_pages(u32 block_size_bytes)
{
	u32 a = PAGE_SIZE;
	u32 b = block_size_bytes;
	u32 r;

	/* Find greatest common divisor using the Euclidian algorithm. */
	do {
		r = a % b;
		a = b;
		b = r;
	} while (b != 0);

	return PHYS_PFN(PAGE_SIZE * block_size_bytes / a);
}

int __init tag_storage_probe(struct reserved_mem *rmem)
{
	struct tag_region *region;
	u32 block_size_bytes;
	int ret;

	if (num_tag_regions == MAX_TAG_REGIONS) {
		pr_err("Exceeded maximum number of tag storage regions");
		goto out_err;
	}

	region = &tag_regions[num_tag_regions];
	region->tag_range.start = PHYS_PFN(rmem->base);
	region->tag_range.end = PHYS_PFN(rmem->base + rmem->size - 1);

	ret = of_flat_read_u32(rmem->fdt_node, "block-size", &block_size_bytes);
	if (ret || block_size_bytes == 0) {
		pr_err("Invalid or missing 'block-size' property");
		goto out_err;
	}

	region->block_size_pages = get_block_size_pages(block_size_bytes);
	if (range_len(&region->tag_range) % region->block_size_pages != 0) {
		pr_err("Tag storage region size 0x%llx pages is not a multiple of block size 0x%x pages",
		       range_len(&region->tag_range), region->block_size_pages);
		goto out_err;
	}

	ret = of_flat_read_u32(rmem->fdt_node, "tagged-memory", &region->mem_phandle);
	if (ret) {
		pr_err("Invalid or missing 'tagged-memory' property");
		goto out_err;
	}

	num_tag_regions++;
	return 0;

out_err:
	num_tag_regions = 0;
	return -EINVAL;
}
RESERVEDMEM_OF_DECLARE(tag_storage, "arm,mte-tag-storage", tag_storage_probe);

static int __init mte_find_tagged_memory_regions(void)
{
	struct device_node *mem_dev;
	struct tag_region *region;
	struct range *mem_range;
	const __be32 *reg;
	u64 addr, size;
	int i;

	for (i = 0; i < num_tag_regions; i++) {
		region = &tag_regions[i];
		mem_range = &region->mem_range;

		mem_dev = of_find_node_by_phandle(region->mem_phandle);
		if (!mem_dev) {
			pr_err("Cannot find tagged memory node");
			goto out;
		}

		reg = of_get_property(mem_dev, "reg", NULL);
		if (!reg) {
			pr_err("Invalid tagged memory node");
			goto out_put_mem;
		}

		addr = of_translate_address(mem_dev, reg);
		if (addr == OF_BAD_ADDR) {
			pr_err("Invalid memory address");
			goto out_put_mem;
		}

		size = of_read_number(reg + of_n_addr_cells(mem_dev), of_n_size_cells(mem_dev));
		if (!size) {
			pr_err("Invalid memory size");
			goto out_put_mem;
		}

		mem_range->start = PHYS_PFN(addr);
		mem_range->end = PHYS_PFN(addr + size - 1);

		of_node_put(mem_dev);
	}

	return 0;

out_put_mem:
	of_node_put(mem_dev);
out:
	return -EINVAL;
}

static void __init mte_split_tag_region(struct tag_region *region, unsigned long last_tag_pfn)
{
	struct tag_region *new_region;
	unsigned long last_mem_pfn;

	new_region = &tag_regions[num_tag_regions];
	last_mem_pfn = region->mem_range.start + (last_tag_pfn - region->tag_range.start) * 32;

	new_region->mem_range.start = last_mem_pfn + 1;
	new_region->mem_range.end = region->mem_range.end;
	region->mem_range.end = last_mem_pfn;

	new_region->tag_range.start = last_tag_pfn + 1;
	new_region->tag_range.end = region->tag_range.end;
	region->tag_range.end = last_tag_pfn;

	new_region->block_size_pages = region->block_size_pages;

	num_tag_regions++;
}

/*
 * Split any tag region that spans multiple zones - CMA will fail if that
 * happens.
 */
static int __init mte_split_tag_regions(void)
{
	struct tag_region *region;
	struct range *tag_range;
	struct zone *zone;
	unsigned long pfn;
	int i;

	for (i = 0; i < num_tag_regions; i++) {
		region = &tag_regions[i];
		tag_range = &region->tag_range;
		zone = page_zone(pfn_to_page(tag_range->start));

		for (pfn = tag_range->start + 1; pfn <= tag_range->end; pfn++) {
			if (page_zone(pfn_to_page(pfn)) == zone)
				continue;

			if (WARN_ON_ONCE(pfn % region->block_size_pages))
				goto out_err;

			if (num_tag_regions == MAX_TAG_REGIONS)
				goto out_err;

			mte_split_tag_region(&tag_regions[i], pfn - 1);
			/* Move on to the next region. */
			break;
		}
	}

	return 0;

out_err:
	pr_err("Error splitting tag storage region 0x%llx-0x%llx spanning multiple zones",
		PFN_PHYS(tag_range->start), PFN_PHYS(tag_range->end + 1) - 1);
	return -EINVAL;
}

void __init mte_init_tag_storage(void)
{
	unsigned long long mem_end;
	struct tag_region *region;
	unsigned long pfn, order;
	u64 start, end;
	int i, j, ret;

	/*
	 * Tag storage memory requires that tag storage pages in use for data
	 * are always migratable when they need to be repurposed to store tags.
	 * If ARCH_KEEP_MEMBLOCK is enabled, kexec will not scan reserved
	 * memblocks when trying to find a suitable location for the kernel
	 * image. This means that kexec will not use tag storage pages for
	 * copying the kernel, and the pages will remain migratable.
	 *
	 * Add the check in case arm64 stops selecting ARCH_KEEP_MEMBLOCK by
	 * default.
	 */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_ARCH_KEEP_MEMBLOCK));

	if (num_tag_regions == 0)
		return;

	ret = mte_find_tagged_memory_regions();
	if (ret)
		goto out_disabled;

	mem_end = PHYS_PFN(memblock_end_of_DRAM());

	/*
	 * MTE is disabled, tag storage pages can be used like any other pages.
	 * The only restriction is that the pages cannot be used by kexec
	 * because the memory remains marked as reserved in the memblock
	 * allocator.
	 */
	if (!system_supports_mte()) {
		for (i = 0; i< num_tag_regions; i++) {
			start = tag_regions[i].tag_range.start;
			end = tag_regions[i].tag_range.end;

			/* end is inclusive, mem_end is not */
			if (end >= mem_end)
				end = mem_end - 1;
			if (end < start)
				continue;
			for (pfn = start; pfn <= end; pfn++)
				free_reserved_page(pfn_to_page(pfn));
		}
		goto out_disabled;
	}

	/*
	 * The kernel allocates memory in non-preemptible contexts, which makes
	 * migration impossible when reserving the associated tag storage. The
	 * only in-kernel user of tagged pages is HW KASAN.
	 */
	if (kasan_hw_tags_enabled()) {
		pr_info("KASAN HW tags incompatible with MTE tag storage management");
		goto out_disabled;
	}

	/*
	 * Check that tag storage is addressable by the kernel.
	 * cma_init_reserved_mem(), unlike cma_declare_contiguous_nid(), doesn't
	 * perform this check.
	 */
	for (i = 0; i< num_tag_regions; i++) {
		start = tag_regions[i].tag_range.start;
		end = tag_regions[i].tag_range.end;

		if (end >= mem_end) {
			pr_err("Tag region 0x%llx-0x%llx outside addressable memory",
				PFN_PHYS(start), PFN_PHYS(end + 1) - 1);
			goto out_disabled;
		}
	}

	ret = mte_split_tag_regions();
	if (ret)
		goto out_disabled;

	for (i = 0; i < num_tag_regions; i++) {
		region = &tag_regions[i];

		/* Tag storage pages are managed in block_size_pages chunks. */
		if (is_power_of_2(region->block_size_pages))
			order = ilog2(region->block_size_pages);
		else
			order = 0;

		ret = cma_init_reserved_mem(PFN_PHYS(region->tag_range.start),
				PFN_PHYS(range_len(&region->tag_range)),
				order, NULL, &region->cma);
		if (ret) {
			for (j = 0; j < i; j++)
				cma_remove_mem(&region->cma);
			goto out_disabled;
		}

		/* Keep pages reserved if activation fails. */
		cma_reserve_pages_on_error(region->cma);
	}

	return;

out_disabled:
	num_tag_regions = 0;
	pr_info("MTE tag storage region management disabled");
}

static int __init mte_enable_tag_storage(void)
{
	struct range *tag_range;
	struct cma *cma;
	int i, ret;

	if (num_tag_regions == 0)
		return 0;

	for (i = 0; i < num_tag_regions; i++) {
		tag_range = &tag_regions[i].tag_range;
		cma = tag_regions[i].cma;
		/*
		 * CMA will keep the pages as reserved when the region fails
		 * activation.
		 */
		if (PageReserved(pfn_to_page(tag_range->start)))
			goto out_disabled;
	}

	static_branch_enable(&tag_storage_enabled_key);
	pr_info("MTE tag storage region management enabled");

	return 0;

out_disabled:
	for (i = 0; i < num_tag_regions; i++) {
		tag_range = &tag_regions[i].tag_range;
		cma = tag_regions[i].cma;

		if (PageReserved(pfn_to_page(tag_range->start)))
			continue;

		/* Try really hard to reserve the tag storage. */
		ret = cma_alloc(cma, range_len(tag_range), 8, true);
		/*
		 * Tag storage is still in use for data, memory and/or tag
		 * corruption will ensue.
		 */
		WARN_ON_ONCE(ret);
	}
	num_tag_regions = 0;
	pr_info("MTE tag storage region management disabled");

	return -EINVAL;
}
arch_initcall(mte_enable_tag_storage);

static void page_set_tag_storage_reserved(struct page *page, int order)
{
	int i;

	for (i = 0; i < (1 << order); i++)
		set_bit(PG_tag_storage_reserved, &(page + i)->flags);
}

static void block_ref_add(unsigned long block, struct tag_region *region, int order)
{
	int count;

	count = min(1u << order, 32 * region->block_size_pages);
	page_ref_add(pfn_to_page(block), count);
}

static int block_ref_sub_return(unsigned long block, struct tag_region *region, int order)
{
	int count;

	count = min(1u << order, 32 * region->block_size_pages);
	return page_ref_sub_return(pfn_to_page(block), count);
}

static bool tag_storage_block_is_reserved(unsigned long block)
{
	return xa_load(&tag_blocks_reserved, block) != NULL;
}

static int tag_storage_reserve_block(unsigned long block, struct tag_region *region, int order)
{
	int ret;

	ret = xa_err(xa_store(&tag_blocks_reserved, block, pfn_to_page(block), GFP_KERNEL));
	if (!ret)
		block_ref_add(block, region, order);

	return ret;
}

static int order_to_num_blocks(int order, u32 block_size_pages)
{
	int num_tag_storage_pages = max((1 << order) / 32, 1);

	return DIV_ROUND_UP(num_tag_storage_pages, block_size_pages);
}

static int tag_storage_find_block_in_region(struct page *page, unsigned long *blockp,
					    struct tag_region *region)
{
	struct range *tag_range = &region->tag_range;
	struct range *mem_range = &region->mem_range;
	u64 page_pfn = page_to_pfn(page);
	u64 block, block_offset;

	if (!(mem_range->start <= page_pfn && page_pfn <= mem_range->end))
		return -ERANGE;

	block_offset = (page_pfn - mem_range->start) / 32;
	block = tag_range->start + rounddown(block_offset, region->block_size_pages);

	if (block + region->block_size_pages - 1 > tag_range->end) {
		pr_err("Block 0x%llx-0x%llx is outside tag region 0x%llx-0x%llx\n",
			PFN_PHYS(block), PFN_PHYS(block + region->block_size_pages + 1) - 1,
			PFN_PHYS(tag_range->start), PFN_PHYS(tag_range->end + 1) - 1);
		return -ERANGE;
	}
	*blockp = block;

	return 0;

}

static int tag_storage_find_block(struct page *page, unsigned long *block,
				  struct tag_region **region)
{
	int i, ret;

	for (i = 0; i < num_tag_regions; i++) {
		ret = tag_storage_find_block_in_region(page, block, &tag_regions[i]);
		if (ret == 0) {
			*region = &tag_regions[i];
			return 0;
		}
	}

	return -EINVAL;
}

bool page_tag_storage_reserved(struct page *page)
{
	return test_bit(PG_tag_storage_reserved, &page->flags);
}

int reserve_tag_storage(struct page *page, int order, gfp_t gfp)
{
	unsigned long start_block, end_block;
	struct tag_region *region;
	unsigned long block;
	unsigned long flags;
	int ret = 0;

	VM_WARN_ON_ONCE(!preemptible());

	if (page_tag_storage_reserved(page))
		return 0;

	/*
	 * __alloc_contig_migrate_range() ignores gfp when allocating the
	 * destination page for migration. Regardless, massage gfp flags and
	 * remove __GFP_TAGGED to avoid recursion in case gfp stops being
	 * ignored.
	 */
	gfp &= ~__GFP_TAGGED;
	if (!(gfp & __GFP_NORETRY))
		gfp |= __GFP_RETRY_MAYFAIL;

	ret = tag_storage_find_block(page, &start_block, &region);
	if (WARN_ONCE(ret, "Missing tag storage block for pfn 0x%lx", page_to_pfn(page)))
		return -EINVAL;
	end_block = start_block + order_to_num_blocks(order, region->block_size_pages);

	mutex_lock(&tag_blocks_lock);

	/* Check again, this time with the lock held. */
	if (page_tag_storage_reserved(page))
		goto out_unlock;

	/* Make sure existing entries are not freed from out under out feet. */
	xa_lock_irqsave(&tag_blocks_reserved, flags);
	for (block = start_block; block < end_block; block += region->block_size_pages) {
		if (tag_storage_block_is_reserved(block))
			block_ref_add(block, region, order);
	}
	xa_unlock_irqrestore(&tag_blocks_reserved, flags);

	for (block = start_block; block < end_block; block += region->block_size_pages) {
		/* Refcount incremented above. */
		if (tag_storage_block_is_reserved(block))
			continue;

		ret = cma_alloc_range(region->cma, block, region->block_size_pages, 3, gfp);
		/* Should never happen. */
		VM_WARN_ON_ONCE(ret == -EEXIST);
		if (ret)
			goto out_error;

		ret = tag_storage_reserve_block(block, region, order);
		if (ret) {
			cma_release(region->cma, pfn_to_page(block), region->block_size_pages);
			goto out_error;
		}
	}

	page_set_tag_storage_reserved(page, order);
out_unlock:
	mutex_unlock(&tag_blocks_lock);

	return 0;

out_error:
	xa_lock_irqsave(&tag_blocks_reserved, flags);
	for (block = start_block; block < end_block; block += region->block_size_pages) {
		if (tag_storage_block_is_reserved(block) &&
		    block_ref_sub_return(block, region, order) == 1) {
			__xa_erase(&tag_blocks_reserved, block);
			cma_release(region->cma, pfn_to_page(block), region->block_size_pages);
		}
	}
	xa_unlock_irqrestore(&tag_blocks_reserved, flags);

	mutex_unlock(&tag_blocks_lock);

	return ret;
}

void free_tag_storage(struct page *page, int order)
{
	unsigned long block, start_block, end_block;
	struct tag_region *region;
	unsigned long flags;
	int ret;

	ret = tag_storage_find_block(page, &start_block, &region);
	if (WARN_ONCE(ret, "Missing tag storage block for pfn 0x%lx", page_to_pfn(page)))
		return;

	end_block = start_block + order_to_num_blocks(order, region->block_size_pages);

	xa_lock_irqsave(&tag_blocks_reserved, flags);
	for (block = start_block; block < end_block; block += region->block_size_pages) {
		if (WARN_ONCE(!tag_storage_block_is_reserved(block),
		    "Block 0x%lx is not reserved for pfn 0x%lx", block, page_to_pfn(page)))
			continue;

		if (block_ref_sub_return(block, region, order) == 1) {
			__xa_erase(&tag_blocks_reserved, block);
			cma_release(region->cma, pfn_to_page(block), region->block_size_pages);
		}
	}
	xa_unlock_irqrestore(&tag_blocks_reserved, flags);
}

void arch_alloc_page(struct page *page, int order, gfp_t gfp)
{
	if (tag_storage_enabled() && alloc_requires_tag_storage(gfp))
		reserve_tag_storage(page, order, gfp);
}
