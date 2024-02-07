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

static int kvm_ptdump_guest_show(struct seq_file *m, void *)
{
	struct kvm *guest_kvm = m->private;
	struct kvm_s2_mmu *mmu = &guest_kvm->arch.mmu;
	struct pg_state parser_state = {0};
	int ret;

	write_lock(&guest_kvm->mmu_lock);
	ret = kvm_ptdump_show_common(m, mmu->pgt, &parser_state);
	write_unlock(&guest_kvm->mmu_lock);

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
