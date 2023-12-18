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

static bool is_fwb_enabled(const struct pg_state *m)
{
	struct kvm_pgtable_snapshot *snapshot = m->seq->private;
	struct kvm_pgtable *pgtable = &snapshot->pgtable;
	bool fwb_enabled = false;

	if (cpus_have_final_cap(ARM64_HAS_STAGE2_FWB))
		fwb_enabled = !(pgtable->flags & KVM_PGTABLE_S2_NOFWB);

	return fwb_enabled;
}

static bool is_pkvm_enabled(const struct pg_state *m)
{
	return is_protected_kvm_enabled();
}

static const struct prot_bits stage2_pte_bits[] = {
	{
		.mask	= PTE_VALID,
		.val	= PTE_VALID,
		.set	= " ",
		.clear	= "F",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.val	= KVM_PTE_LEAF_ATTR_HI_S2_XN,
		.set	= "XN",
		.clear	= "  ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R,
		.set	= "R",
		.clear	= " ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W,
		.set	= "W",
		.clear	= " ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_AF,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_AF,
		.set	= "AF",
		.clear	= "  ",
	}, {
		.mask	= PTE_NG,
		.val	= PTE_NG,
		.set	= "FnXS",
		.clear	= "  ",
	}, {
		.mask	= PTE_CONT,
		.val	= PTE_CONT,
		.set	= "CON",
		.clear	= "   ",
	}, {
		.mask	= PTE_TABLE_BIT,
		.val	= PTE_TABLE_BIT,
		.set	= "   ",
		.clear	= "BLK",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR | PTE_VALID,
		.val	= PTE_S2_MEMATTR(MT_S2_DEVICE_nGnRE) | PTE_VALID,
		.set	= "DEVICE/nGnRE",
		.feature_off	= is_fwb_enabled,
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR | PTE_VALID,
		.val	= PTE_S2_MEMATTR(MT_S2_FWB_DEVICE_nGnRE) | PTE_VALID,
		.set	= "DEVICE/nGnRE FWB",
		.feature_on	= is_fwb_enabled,
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR | PTE_VALID,
		.val	= PTE_S2_MEMATTR(MT_S2_NORMAL) | PTE_VALID,
		.set	= "MEM/NORMAL",
		.feature_off	= is_fwb_enabled,
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_MEMATTR | PTE_VALID,
		.val	= PTE_S2_MEMATTR(MT_S2_FWB_NORMAL) | PTE_VALID,
		.set	= "MEM/NORMAL FWB",
		.feature_on	= is_fwb_enabled,
	}, {
		.mask	= KVM_INVALID_PTE_OWNER_MASK | PTE_VALID,
		.val	= FIELD_PREP_CONST(KVM_INVALID_PTE_OWNER_MASK,
					   PKVM_ID_HYP),
		.set	= "HYP",
	}, {
		.mask	= KVM_INVALID_PTE_OWNER_MASK | PTE_VALID,
		.val	= FIELD_PREP_CONST(KVM_INVALID_PTE_OWNER_MASK,
					   PKVM_ID_FFA),
		.set	= "FF-A",
	}, {
		.mask	= __PKVM_PAGE_RESERVED | PTE_VALID,
		.val	= PKVM_PAGE_OWNED | PTE_VALID,
		.set	= "PKVM_PAGE_OWNED",
		.feature_on	= is_pkvm_enabled,
	}, {
		.mask   = __PKVM_PAGE_RESERVED | PTE_VALID,
		.val	= PKVM_PAGE_SHARED_OWNED | PTE_VALID,
		.set	= "PKVM_PAGE_SHARED_OWNED",
		.feature_on     = is_pkvm_enabled,
	}, {
		.mask	= __PKVM_PAGE_RESERVED | PTE_VALID,
		.val	= PKVM_PAGE_SHARED_BORROWED | PTE_VALID,
		.set	= "PKVM_PAGE_SHARED_BORROWED",
		.feature_on     = is_pkvm_enabled,
	}, {
		.mask	= PKVM_NOPAGE | PTE_VALID,
		.val	= PKVM_NOPAGE,
		.set	= "PKVM_NOPAGE",
		.feature_on     = is_pkvm_enabled,
	}, {
		.mask	= KVM_PGTABLE_PROT_SW0,
		.val	= KVM_PGTABLE_PROT_SW0,
		.set    = "SW0",
		.feature_off	= is_pkvm_enabled,
	}, {
		.mask	= KVM_PGTABLE_PROT_SW1,
		.val	= KVM_PGTABLE_PROT_SW1,
		.set	= "SW1",
		.feature_off	= is_pkvm_enabled,
	}, {
		.mask   = KVM_PGTABLE_PROT_SW2,
		.val	= KVM_PGTABLE_PROT_SW2,
		.set	= "SW2",
		.feature_off	= is_pkvm_enabled,
	}, {
		.mask   = KVM_PGTABLE_PROT_SW3,
		.val	= KVM_PGTABLE_PROT_SW3,
		.set	= "SW3",
		.feature_off	= is_pkvm_enabled,
	},
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
	} else {
		info = inode->i_private;
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

static int kvm_ptdump_build_levels(struct pg_level *level, unsigned int start_level)
{
	static const char * const level_names[] = {"PGD", "PUD", "PMD", "PTE"};
	int i, j, name_index;

	if (start_level > 2) {
		pr_err("invalid start_level %u\n", start_level);
		return -EINVAL;
	}

	for (i = start_level; i < KVM_PGTABLE_MAX_LEVELS; i++) {
		name_index = i - start_level;
		name_index += name_index * start_level;

		level[i].name	= level_names[name_index];
		level[i].num	= ARRAY_SIZE(stage2_pte_bits);
		level[i].bits	= stage2_pte_bits;

		for (j = 0; j < level[i].num; j++)
			level[i].mask |= level[i].bits[j].mask;
	}

	return 0;
}

static int kvm_ptdump_visitor(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct pg_state *st = ctx->arg;
	struct ptdump_state *pt_st = &st->ptdump;

	note_page(pt_st, ctx->addr, ctx->level, ctx->old);
	return 0;
}

static int kvm_ptdump_show_common(struct seq_file *m,
				  struct kvm_pgtable *pgtable)
{
	u64 ipa_size;
	char ipa_description[32];
	struct pg_state st;
	struct addr_marker ipa_addr_markers[3] = {0};
	struct pg_level pg_level_descr[KVM_PGTABLE_MAX_LEVELS] = {0};
	struct kvm_pgtable_walker walker = (struct kvm_pgtable_walker) {
		.cb	= kvm_ptdump_visitor,
		.arg	= &st,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};

	if (kvm_ptdump_build_levels(pg_level_descr, pgtable->start_level) < 0)
		return -EINVAL;

	snprintf(ipa_description, sizeof(ipa_description),
		 "IPA bits %2u start lvl %1u", pgtable->ia_bits,
		 pgtable->start_level);

	ipa_size = BIT(pgtable->ia_bits);
	ipa_addr_markers[0].name = ipa_description;
	ipa_addr_markers[1].start_address = ipa_size;

	st = (struct pg_state) {
		.seq		= m,
		.marker		= &ipa_addr_markers[0],
		.level		= -1,
		.pg_level	= &pg_level_descr[0],
		.ptdump	= {
			.note_page	= note_page,
			.range		= (struct ptdump_range[]) {
				{0, ipa_size},
				{0, 0},
			},
		},
	};

	return kvm_pgtable_walk(pgtable, 0, ipa_size, &walker);
}

static int kvm_host_ptdump_show(struct seq_file *m, void *)
{
	struct kvm_pgtable_snapshot *snapshot = m->private;

	return kvm_ptdump_show_common(m, &snapshot->pgtable);
}

static int kvm_ptdump_show(struct seq_file *m, void *)
{
	struct kvm *guest_kvm = m->private;
	struct kvm_s2_mmu *mmu = &guest_kvm->arch.mmu;
	int ret;

	write_lock(&guest_kvm->mmu_lock);
	ret = kvm_ptdump_show_common(m, mmu->pgt);
	write_unlock(&guest_kvm->mmu_lock);

	return ret;
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
	host_reg.show_ptdump_info = kvm_host_ptdump_show;

	kvm_ptdump_debugfs_register(&host_reg, "host_page_tables",
				    kvm_debugfs_dir);
}

int kvm_ptdump_register_guest(struct kvm *kvm)
{
	debugfs_create_file("stage2_page_tables", 0400, kvm->debugfs_dentry,
			    kvm, &kvm_ptdump_fops);
	return 0;
}

static int __init kvm_host_ptdump_init(void)
{
	host_reg.priv = (void *)host_s2_pgtable_pages();
	return 0;
}

device_initcall(kvm_host_ptdump_init);
