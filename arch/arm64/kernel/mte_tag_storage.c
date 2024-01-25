// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support for dynamic tag storage.
 *
 * Copyright (C) 2023 ARM Ltd.
 */

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

struct tag_region {
	struct range mem_range;	/* Memory associated with the tag storage, in PFNs. */
	struct range tag_range;	/* Tag storage memory, in PFNs. */
	u32 block_size_pages;	/* Tag block size, in pages. */
	phandle mem_phandle;	/* phandle for the associated memory node. */
};

#define MAX_TAG_REGIONS	32

static struct tag_region tag_regions[MAX_TAG_REGIONS];
static int num_tag_regions;

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

void __init mte_init_tag_storage(void)
{
	int ret;

	if (num_tag_regions == 0)
		return;

	ret = mte_find_tagged_memory_regions();
	if (ret)
		goto out_disabled;

	return;

out_disabled:
	num_tag_regions = 0;
	pr_info("MTE tag storage region management disabled");
}
