/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ARM Generic Interrupt Controller (GIC) host specific defines
 */

#ifndef SELFTEST_KVM_VGIC_H
#define SELFTEST_KVM_VGIC_H

#include <linux/kvm.h>

#include "kvm_util.h"

#define REDIST_REGION_ATTR_ADDR(count, base, flags, index) \
	(((uint64_t)(count) << 52) | \
	((uint64_t)((base) >> 16) << 16) | \
	((uint64_t)(flags) << 12) | \
	index)

int vgic_v3_setup(struct kvm_vm *vm, unsigned int nr_vcpus, uint32_t nr_irqs);

#define VGIC_MAX_RESERVED	1023

void kvm_irq_set_level_info(int gic_fd, uint32_t intid, int level);
int _kvm_irq_set_level_info(int gic_fd, uint32_t intid, int level);

void kvm_arm_irq_line(struct kvm_vm *vm, uint32_t intid, int level);
int _kvm_arm_irq_line(struct kvm_vm *vm, uint32_t intid, int level);

/* The vcpu arg only applies to private interrupts. */
void kvm_irq_write_ispendr(int gic_fd, uint32_t intid, struct kvm_vcpu *vcpu);
void kvm_irq_write_isactiver(int gic_fd, uint32_t intid, struct kvm_vcpu *vcpu);

#define KVM_IRQCHIP_NUM_PINS	(1020 - 32)

void vgic_rdist_enable_lpis(int gic_fd, struct kvm_vcpu *vcpu,
			    vm_paddr_t cfg_table, size_t cfg_table_size,
			    vm_paddr_t pend_table);

struct vgic_its {
	int	its_fd;
	void 	*cmdq_hva;
	size_t	cmdq_size;
};

struct vgic_its *vgic_its_setup(struct kvm_vm *vm,
				vm_paddr_t coll_tbl, size_t coll_tbl_sz,
				vm_paddr_t device_tbl, size_t device_tbl_sz,
				vm_paddr_t cmdq, size_t cmdq_size);
void vgic_its_destroy(struct vgic_its *its);

void vgic_its_send_mapd_cmd(struct vgic_its *its, u32 device_id,
		            vm_paddr_t itt_base, size_t itt_size, bool valid);
void vgic_its_send_mapc_cmd(struct vgic_its *its, struct kvm_vcpu *vcpu,
			    u32 collection_id, bool valid);
void vgic_its_send_mapti_cmd(struct vgic_its *its, u32 device_id,
			     u32 event_id, u32 collection_id, u32 intid);
void vgic_its_send_invall_cmd(struct vgic_its *its, u32 collection_id);

#endif // SELFTEST_KVM_VGIC_H
