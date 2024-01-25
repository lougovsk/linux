/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */
#ifndef __ASM_MTE_TAG_STORAGE_H
#define __ASM_MTE_TAG_STORAGE_H

#ifdef CONFIG_ARM64_MTE_TAG_STORAGE
void mte_init_tag_storage(void);
#else
static inline void mte_init_tag_storage(void)
{
}
#endif /* CONFIG_ARM64_MTE_TAG_STORAGE */

#endif /* __ASM_MTE_TAG_STORAGE_H  */
