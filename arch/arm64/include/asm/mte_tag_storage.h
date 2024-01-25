/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */
#ifndef __ASM_MTE_TAG_STORAGE_H
#define __ASM_MTE_TAG_STORAGE_H

#ifndef __ASSEMBLY__

#include <linux/mm_types.h>

#include <asm/mte.h>

extern void dcache_inval_tags_poc(unsigned long start, unsigned long end);

#ifdef CONFIG_ARM64_MTE_TAG_STORAGE

DECLARE_STATIC_KEY_FALSE(tag_storage_enabled_key);

static inline bool tag_storage_enabled(void)
{
	return static_branch_likely(&tag_storage_enabled_key);
}

void mte_init_tag_storage(void);

static inline bool alloc_requires_tag_storage(gfp_t gfp)
{
	return gfp & __GFP_TAGGED;
}
int reserve_tag_storage(struct page *page, int order, gfp_t gfp);
void free_tag_storage(struct page *page, int order);

bool page_tag_storage_reserved(struct page *page);
bool page_is_tag_storage(struct page *page);

vm_fault_t handle_folio_missing_tag_storage(struct folio *folio, struct vm_fault *vmf,
					    bool *map_pte);
vm_fault_t mte_try_transfer_swap_tags(swp_entry_t entry, struct page *page);

void tags_by_pfn_lock(void);
void tags_by_pfn_unlock(void);

void *mte_erase_tags_for_pfn(unsigned long pfn);
bool mte_save_tags_for_pfn(void *tags, unsigned long pfn);
void mte_restore_tags_for_pfn(unsigned long start_pfn, int order);
#else
static inline bool tag_storage_enabled(void)
{
	return false;
}
static inline void mte_init_tag_storage(void)
{
}
static inline bool alloc_requires_tag_storage(struct page *page)
{
	return false;
}
static inline int reserve_tag_storage(struct page *page, int order, gfp_t gfp)
{
	return 0;
}
static inline void free_tag_storage(struct page *page, int order)
{
}
static inline bool page_tag_storage_reserved(struct page *page)
{
	return true;
}
#endif /* CONFIG_ARM64_MTE_TAG_STORAGE */

#endif /* !__ASSEMBLY__ */
#endif /* __ASM_MTE_TAG_STORAGE_H  */
