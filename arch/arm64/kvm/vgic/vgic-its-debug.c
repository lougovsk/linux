// SPDX-License-Identifier: GPL-2.0-only
/*
 * vgic-its-debug.c - Debugfs interface for exposing VGIC ITS tables.
 *
 * Copyright (C) 2025 Google
 *
 * This file provides a debugfs interface to display the contents of the
 * VGIC Interrupt Translation Service (ITS) tables. This allows for
 * inspection of the mapping between Event IDs, Interrupt IDs, and target
 * processors. The information is presented in a tabular format through a
 * seq_file interface.
 */

#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>
#include <kvm/arm_vgic.h>
#include "vgic.h"

/**
 * struct vgic_its_iter - Iterator for traversing VGIC ITS tables.
 * @dev: Pointer to the current its_device being processed.
 * @ite: Pointer to the current its_ite within the device being processed.
 *
 * This structure is used to maintain the current position during iteration
 * over the ITS tables. It holds pointers to both the current device and the
 * current ITE within that device.
 */
struct vgic_its_iter {
	struct its_device *dev;
	struct its_ite *ite;
};

/**
 * end_of_iter - Checks if the iterator has reached the end of the ITS tables.
 * @iter: The iterator to check.
 *
 * Return: True if the iterator is at the end, false otherwise.
 */
static inline bool end_of_iter(struct vgic_its_iter *iter)
{
	return !iter->dev && !iter->ite;
}

/**
 * iter_next - Advances the iterator to the next entry in the ITS tables.
 * @its: The VGIC ITS structure.
 * @iter: The iterator to advance.
 *
 * This function moves the iterator to the next ITE within the current device,
 * or to the first ITE of the next device if the current ITE is the last in
 * the device. If the current device is the last device, the iterator is set
 * to indicate the end of iteration.
 */
static void iter_next(struct vgic_its *its, struct vgic_its_iter *iter)
{
	struct its_device *dev = iter->dev;
	struct its_ite *ite = iter->ite;

	if (!ite || list_is_last(&ite->ite_list, &dev->itt_head)) {
		if (list_is_last(&dev->dev_list, &its->device_list)) {
			dev = NULL;
			ite = NULL;
		} else {
			dev = list_next_entry(dev, dev_list);
			ite = list_first_entry_or_null(&dev->itt_head,
						       struct its_ite,
						       ite_list);
		}
	} else {
		ite = list_next_entry(ite, ite_list);
	}

	iter->dev = dev;
	iter->ite = ite;
}

/**
 * vgic_its_debug_start - Start function for the seq_file interface.
 * @s: The seq_file structure.
 * @pos: The starting position (offset).
 *
 * This function initializes the iterator to the beginning of the ITS tables
 * and advances it to the specified position. It acquires the its_lock mutex
 * to protect shared data.
 *
 * Return: An iterator pointer on success, NULL if no devices are found or
 *         the end of the list is reached, or ERR_PTR(-ENOMEM) on memory
 *         allocation failure.
 */
static void *vgic_its_debug_start(struct seq_file *s, loff_t *pos)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter;
	struct its_device *dev;
	loff_t offset = *pos;

	mutex_lock(&its->its_lock);

	dev = list_first_entry_or_null(&its->device_list,
				       struct its_device, dev_list);
	if (!dev)
		return NULL;

	iter = kmalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	iter->dev = dev;
	iter->ite = list_first_entry_or_null(&dev->itt_head,
					     struct its_ite, ite_list);

	while (!end_of_iter(iter) && offset--)
		iter_next(its, iter);

	if (end_of_iter(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

/**
 * vgic_its_debug_next - Next function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 * @pos: The current position (offset).
 *
 * This function advances the iterator to the next entry and increments the
 * position.
 *
 * Return: An iterator pointer on success, or NULL if the end of the list is
 *         reached.
 */
static void *vgic_its_debug_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter = v;

	++*pos;
	iter_next(its, iter);

	if (end_of_iter(iter)) {
		kfree(iter);
		return NULL;
	}
	return iter;
}

/**
 * vgic_its_debug_stop - Stop function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 *
 * This function frees the iterator and releases the its_lock mutex.
 */
static void vgic_its_debug_stop(struct seq_file *s, void *v)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter = v;

	if (!IS_ERR_OR_NULL(iter))
		kfree(iter);
	mutex_unlock(&its->its_lock);
}

/**
 * vgic_its_debug_show - Show function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 *
 * This function formats and prints the ITS table entry information to the
 * seq_file output.
 *
 * Return: 0 on success.
 */
static int vgic_its_debug_show(struct seq_file *s, void *v)
{
	struct vgic_its_iter *iter = v;
	struct its_device *dev = iter->dev;
	struct its_ite *ite = iter->ite;

	if (list_is_first(&ite->ite_list, &dev->itt_head)) {
		seq_printf(s, "\n");
		seq_printf(s, "Device ID: %u, Event ID Range: [0 - %llu]\n",
			   dev->device_id, BIT_ULL(dev->num_eventid_bits) - 1);
		seq_printf(s, "EVENT_ID    INTID  HWINTID   TARGET   COL_ID HW\n");
		seq_printf(s, "-----------------------------------------------\n");
	}

	if (ite && ite->irq && ite->collection) {
		seq_printf(s, "%8u %8u %8u %8u %8u %2d\n",
			   ite->event_id, ite->irq->intid, ite->irq->hwintid,
			   ite->collection->target_addr,
			   ite->collection->collection_id, ite->irq->hw);
	}

	return 0;
}

static const struct seq_operations vgic_its_debug_sops = {
	.start = vgic_its_debug_start,
	.next  = vgic_its_debug_next,
	.stop  = vgic_its_debug_stop,
	.show  = vgic_its_debug_show
};

DEFINE_SEQ_ATTRIBUTE(vgic_its_debug);

/**
 * vgic_its_debug_init - Initializes the debugfs interface for VGIC ITS.
 * @dev: The KVM device structure.
 *
 * This function creates a debugfs file named "vgic-its-state@%its_base"
 * to expose the ITS table information.
 *
 * Return: 0 on success.
 */
int vgic_its_debug_init(struct kvm_device *dev)
{
	struct vgic_its *its = dev->private;
	char name[32];

	snprintf(name, sizeof(name), "vgic-its-state@%llx", (u64)its->vgic_its_base);
	debugfs_create_file(name, 0444, dev->kvm->debugfs_dentry, its, &vgic_its_debug_fops);

	return 0;
}

void vgic_its_debug_destroy(struct kvm_device *dev)
{
}

