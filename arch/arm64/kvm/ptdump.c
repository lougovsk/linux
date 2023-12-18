// SPDX-License-Identifier: GPL-2.0-only
//
// Debug helper used to dump the stage-2 pagetables of the system and their
// associated permissions.
//
// Copyright (C) Google, 2023
// Author: Sebastian Ene <sebastianene@google.com>

#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>

#include <asm/kvm_pkvm.h>
#include <kvm_ptdump.h>


struct kvm_ptdump_register {
	void *(*get_ptdump_info)(struct kvm_ptdump_register *reg);
	void (*put_ptdump_info)(void *priv);
	int (*show_ptdump_info)(struct seq_file *m, void *v);
	void *priv;
};

static int kvm_ptdump_open(struct inode *inode, struct file *file);
static int kvm_ptdump_release(struct inode *inode, struct file *file);
static int kvm_ptdump_show(struct seq_file *m, void *);

static phys_addr_t get_host_pa(void *addr);
static void *get_host_va(phys_addr_t pa);

static const struct file_operations kvm_ptdump_fops = {
	.open		= kvm_ptdump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_ptdump_release,
};

static struct kvm_pgtable_mm_ops ptdump_host_mmops = {
	.phys_to_virt	= get_host_va,
	.virt_to_phys	= get_host_pa,
};

static int kvm_ptdump_open(struct inode *inode, struct file *file)
{
	struct kvm_ptdump_register *reg = inode->i_private;
	void *info = NULL;
	int ret;

	if (reg->get_ptdump_info) {
		info = reg->get_ptdump_info(reg);
		if (!info)
			return -ENOMEM;
	}

	if (!reg->show_ptdump_info)
		reg->show_ptdump_info = kvm_ptdump_show;

	ret = single_open(file, reg->show_ptdump_info, info);
	if (ret && reg->put_ptdump_info)
		reg->put_ptdump_info(info);

	return ret;
}

static int kvm_ptdump_release(struct inode *inode, struct file *file)
{
	struct kvm_ptdump_register *reg = inode->i_private;
	struct seq_file *seq_file = file->private_data;

	if (reg->put_ptdump_info)
		reg->put_ptdump_info(seq_file->private);

	return 0;
}

static int kvm_ptdump_show(struct seq_file *m, void *)
{
	return -EINVAL;
}

static void kvm_ptdump_debugfs_register(struct kvm_ptdump_register *reg,
					const char *name, struct dentry *parent)
{
	debugfs_create_file(name, 0400, parent, reg, &kvm_ptdump_fops);
}

static struct kvm_ptdump_register host_reg;

static size_t host_stage2_get_pgd_len(void)
{
	u32 phys_shift = get_kvm_ipa_limit();
	u64 vtcr = kvm_get_vtcr(read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1),
				read_sanitised_ftr_reg(SYS_ID_AA64MMFR1_EL1),
				phys_shift);
	return (kvm_pgtable_stage2_pgd_size(vtcr) >> PAGE_SHIFT);
}

static phys_addr_t get_host_pa(void *addr)
{
	return __pa(addr);
}

static void *get_host_va(phys_addr_t pa)
{
	return __va(pa);
}

static void kvm_host_put_ptdump_info(void *snap)
{
	void *mc_page;
	size_t i;
	struct kvm_pgtable_snapshot *snapshot;

	if (!snap)
		return;

	snapshot = snap;
	while ((mc_page = pop_hyp_memcache(&snapshot->mc, get_host_va)) != NULL)
		free_page((unsigned long)mc_page);

	if (snapshot->pgd_hva)
		free_pages_exact(snapshot->pgd_hva, snapshot->pgd_pages);

	if (snapshot->used_pages_hva) {
		for (i = 0; i < snapshot->used_pages_indx; i++) {
			mc_page = get_host_va(snapshot->used_pages_hva[i]);
			free_page((unsigned long)mc_page);
		}

		free_pages_exact(snapshot->used_pages_hva, snapshot->num_used_pages);
	}

	free_page((unsigned long)snapshot);
}

static void *kvm_host_get_ptdump_info(struct kvm_ptdump_register *reg)
{
	int i, ret;
	void *mc_page;
	struct kvm_pgtable_snapshot *snapshot;
	size_t memcache_len;

	snapshot = (void *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!snapshot)
		return NULL;

	memset(snapshot, 0, sizeof(struct kvm_pgtable_snapshot));

	snapshot->pgd_pages = host_stage2_get_pgd_len();
	snapshot->pgd_hva = alloc_pages_exact(snapshot->pgd_pages, GFP_KERNEL_ACCOUNT);
	if (!snapshot->pgd_hva)
		goto err;

	memcache_len = (size_t)reg->priv;
	for (i = 0; i < memcache_len; i++) {
		mc_page = (void *)__get_free_page(GFP_KERNEL_ACCOUNT);
		if (!mc_page)
			goto err;

		push_hyp_memcache(&snapshot->mc, mc_page, get_host_pa);
	}

	snapshot->num_used_pages = DIV_ROUND_UP(sizeof(phys_addr_t) * memcache_len,
					     PAGE_SIZE);
	snapshot->used_pages_hva = alloc_pages_exact(snapshot->num_used_pages,
						  GFP_KERNEL_ACCOUNT);
	if (!snapshot->used_pages_hva)
		goto err;

	ret = kvm_call_hyp_nvhe(__pkvm_host_stage2_snapshot, snapshot);
	if (ret) {
		pr_err("ERROR %d snapshot host pagetables\n", ret);
		goto err;
	}

	snapshot->pgtable.pgd = get_host_va((phys_addr_t)snapshot->pgtable.pgd);
	snapshot->pgtable.mm_ops = &ptdump_host_mmops;

	return snapshot;
err:
	kvm_host_put_ptdump_info(snapshot);
	return NULL;
}

void kvm_ptdump_register_host(void)
{
	if (!is_protected_kvm_enabled())
		return;

	host_reg.get_ptdump_info = kvm_host_get_ptdump_info;
	host_reg.put_ptdump_info = kvm_host_put_ptdump_info;

	kvm_ptdump_debugfs_register(&host_reg, "host_page_tables",
				    kvm_debugfs_dir);
}

static int __init kvm_host_ptdump_init(void)
{
	host_reg.priv = (void *)host_s2_pgtable_pages();
	return 0;
}

device_initcall(kvm_host_ptdump_init);
