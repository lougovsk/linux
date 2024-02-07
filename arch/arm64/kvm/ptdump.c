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


#define ADDR_MARKER_LEN		(2)
#define MARKER_MSG_LEN		(32)

static const struct prot_bits stage2_pte_bits[] = {
	{
		.mask	= PTE_VALID,
		.val	= PTE_VALID,
		.set	= " ",
		.clear	= "F",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_HI_S2_XN | PTE_VALID,
		.val	= KVM_PTE_LEAF_ATTR_HI_S2_XN | PTE_VALID,
		.set	= "XN",
		.clear	= "  ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | PTE_VALID,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R | PTE_VALID,
		.set	= "R",
		.clear	= " ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W | PTE_VALID,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W | PTE_VALID,
		.set	= "W",
		.clear	= " ",
	}, {
		.mask	= KVM_PTE_LEAF_ATTR_LO_S2_AF | PTE_VALID,
		.val	= KVM_PTE_LEAF_ATTR_LO_S2_AF | PTE_VALID,
		.set	= "AF",
		.clear	= "  ",
	}, {
		.mask	= PTE_NG,
		.val	= PTE_NG,
		.set	= "FnXS",
		.clear	= "  ",
	}, {
		.mask	= PTE_CONT | PTE_VALID,
		.val	= PTE_CONT | PTE_VALID,
		.set	= "CON",
		.clear	= "   ",
	}, {
		.mask	= PTE_TABLE_BIT,
		.val	= PTE_TABLE_BIT,
		.set	= "   ",
		.clear	= "BLK",
	}, {
		.mask	= KVM_PGTABLE_PROT_SW0,
		.val	= KVM_PGTABLE_PROT_SW0,
		.set	= "SW0", /* PKVM_PAGE_SHARED_OWNED */
	}, {
		.mask   = KVM_PGTABLE_PROT_SW1,
		.val	= KVM_PGTABLE_PROT_SW1,
		.set	= "SW1", /* PKVM_PAGE_SHARED_BORROWED */
	}, {
		.mask	= KVM_PGTABLE_PROT_SW2,
		.val	= KVM_PGTABLE_PROT_SW2,
		.set	= "SW2",
	}, {
		.mask   = KVM_PGTABLE_PROT_SW3,
		.val	= KVM_PGTABLE_PROT_SW3,
		.set	= "SW3",
	},
};

static int kvm_ptdump_guest_open(struct inode *inode, struct file *file);
static int kvm_ptdump_guest_show(struct seq_file *m, void *);

static const struct file_operations kvm_ptdump_guest_fops = {
	.open		= kvm_ptdump_guest_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int kvm_ptdump_guest_open(struct inode *inode, struct file *file)
{
	return single_open(file, kvm_ptdump_guest_show, inode->i_private);
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
				  struct kvm_pgtable *pgtable,
				  struct pg_state *parser_state)
{
	struct kvm_pgtable_walker walker = (struct kvm_pgtable_walker) {
		.cb     = kvm_ptdump_visitor,
		.arg	= parser_state,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};

	return kvm_pgtable_walk(pgtable, 0, BIT(pgtable->ia_bits), &walker);
}

static void kvm_ptdump_build_levels(struct pg_level *level, u32 start_lvl)
{
	static const char * const level_names[] = {"PGD", "PUD", "PMD", "PTE"};
	u32 i = 0;
	u64 mask_lvl = 0;

	if (start_lvl > 2) {
		pr_err("invalid start_lvl %u\n", start_lvl);
		return;
	}

	for (i = 0; i < ARRAY_SIZE(stage2_pte_bits); i++)
		mask_lvl |= stage2_pte_bits[i].mask;

	for (i = start_lvl; i <= KVM_PGTABLE_LAST_LEVEL; i++) {
		level[i].name = level_names[i];
		level[i].num = ARRAY_SIZE(stage2_pte_bits);
		level[i].bits = stage2_pte_bits;
		level[i].mask = mask_lvl;
	}

	if (start_lvl > 0)
		level[start_lvl].name = level_names[0];
}

static int kvm_ptdump_parser_init(struct pg_state *st,
				  struct kvm_pgtable *pgtable,
				  struct seq_file *m)
{
	struct addr_marker *ipa_addr_marker;
	char *marker_msg;
	struct pg_level *level_descr;
	struct ptdump_range *range;

	ipa_addr_marker = kzalloc(sizeof(struct addr_marker) * ADDR_MARKER_LEN,
				  GFP_KERNEL_ACCOUNT);
	if (!ipa_addr_marker)
		return -ENOMEM;

	marker_msg = kzalloc(MARKER_MSG_LEN, GFP_KERNEL_ACCOUNT);
	if (!marker_msg)
		goto free_with_marker;

	level_descr = kzalloc(sizeof(struct pg_level) * (KVM_PGTABLE_LAST_LEVEL + 1),
			      GFP_KERNEL_ACCOUNT);
	if (!level_descr)
		goto free_with_msg;

	range = kzalloc(sizeof(struct ptdump_range) * ADDR_MARKER_LEN,
			GFP_KERNEL_ACCOUNT);
	if (!range)
		goto free_with_level;

	kvm_ptdump_build_levels(level_descr, pgtable->start_level);

	snprintf(marker_msg, MARKER_MSG_LEN, "IPA bits %2u start lvl %1d",
		 pgtable->ia_bits, pgtable->start_level);

	ipa_addr_marker[0].name = marker_msg;
	ipa_addr_marker[1].start_address = BIT(pgtable->ia_bits);
	range[0].end = BIT(pgtable->ia_bits);

	st->seq = m;
	st->marker = ipa_addr_marker;
	st->level = -1,
	st->pg_level = level_descr,
	st->ptdump.range = range;
	return 0;

free_with_level:
	kfree(level_descr);
free_with_msg:
	kfree(marker_msg);
free_with_marker:
	kfree(ipa_addr_marker);
	return -ENOMEM;
}

static void kvm_ptdump_parser_teardown(struct pg_state *st)
{
	const struct addr_marker *ipa_addr_marker = st->marker;

	kfree(ipa_addr_marker[0].name);
	kfree(ipa_addr_marker);
	kfree(st->pg_level);
	kfree(st->ptdump.range);
}

static int kvm_ptdump_guest_show(struct seq_file *m, void *)
{
	struct kvm *guest_kvm = m->private;
	struct kvm_s2_mmu *mmu = &guest_kvm->arch.mmu;
	struct pg_state parser_state = {0};
	int ret;

	ret = kvm_ptdump_parser_init(&parser_state, mmu->pgt, m);
	if (ret)
		return ret;

	write_lock(&guest_kvm->mmu_lock);
	ret = kvm_ptdump_show_common(m, mmu->pgt, &parser_state);
	write_unlock(&guest_kvm->mmu_lock);

	kvm_ptdump_parser_teardown(&parser_state);
	return ret;
}

int kvm_ptdump_guest_register(struct kvm *kvm)
{
	struct dentry *parent;

	parent = debugfs_create_file("stage2_page_tables", 0400,
				     kvm->debugfs_dentry, kvm,
				     &kvm_ptdump_guest_fops);
	if (IS_ERR(parent))
		return PTR_ERR(parent);
	return 0;
}
