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

static const struct file_operations kvm_ptdump_fops = {
	.open		= kvm_ptdump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_ptdump_release,
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

void kvm_ptdump_register_host(void)
{
	if (!is_protected_kvm_enabled())
		return;

	kvm_ptdump_debugfs_register(&host_reg, "host_page_tables",
				    kvm_debugfs_dir);
}

static int __init kvm_host_ptdump_init(void)
{
	host_reg.priv = (void *)host_s2_pgtable_pages();
	return 0;
}

device_initcall(kvm_host_ptdump_init);
