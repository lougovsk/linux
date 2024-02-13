// SPDX-License-Identifier: GPL-2.0
/*
 * ARM Generic Interrupt Controller (GIC) v3 host support
 */

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/sizes.h>
#include <asm/cputype.h>
#include <asm/kvm_para.h>
#include <asm/kvm.h>

#include "kvm_util.h"
#include "vgic.h"
#include "gic.h"
#include "gic_v3.h"
#include "processor.h"

/*
 * vGIC-v3 default host setup
 *
 * Input args:
 *	vm - KVM VM
 *	nr_vcpus - Number of vCPUs supported by this VM
 *
 * Output args: None
 *
 * Return: GIC file-descriptor or negative error code upon failure
 *
 * The function creates a vGIC-v3 device and maps the distributor and
 * redistributor regions of the guest. Since it depends on the number of
 * vCPUs for the VM, it must be called after all the vCPUs have been created.
 */
int vgic_v3_setup(struct kvm_vm *vm, unsigned int nr_vcpus, uint32_t nr_irqs)
{
	int gic_fd;
	uint64_t attr;
	struct list_head *iter;
	unsigned int nr_gic_pages, nr_vcpus_created = 0;

	TEST_ASSERT(nr_vcpus, "Number of vCPUs cannot be empty\n");

	/*
	 * Make sure that the caller is infact calling this
	 * function after all the vCPUs are added.
	 */
	list_for_each(iter, &vm->vcpus)
		nr_vcpus_created++;
	TEST_ASSERT(nr_vcpus == nr_vcpus_created,
			"Number of vCPUs requested (%u) doesn't match with the ones created for the VM (%u)\n",
			nr_vcpus, nr_vcpus_created);

	/* Distributor setup */
	gic_fd = __kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3);
	if (gic_fd < 0)
		return gic_fd;

	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs);

	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
			    KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);

	attr = GICD_BASE_GPA;
	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
			    KVM_VGIC_V3_ADDR_TYPE_DIST, &attr);
	nr_gic_pages = vm_calc_num_guest_pages(vm->mode, KVM_VGIC_V3_DIST_SIZE);
	virt_map(vm, GICD_BASE_GPA, GICD_BASE_GPA, nr_gic_pages);

	/* Redistributor setup */
	attr = REDIST_REGION_ATTR_ADDR(nr_vcpus, GICR_BASE_GPA, 0, 0);
	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
			    KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &attr);
	nr_gic_pages = vm_calc_num_guest_pages(vm->mode,
						KVM_VGIC_V3_REDIST_SIZE * nr_vcpus);
	virt_map(vm, GICR_BASE_GPA, GICR_BASE_GPA, nr_gic_pages);

	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
			    KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);

	return gic_fd;
}

/* should only work for level sensitive interrupts */
int _kvm_irq_set_level_info(int gic_fd, uint32_t intid, int level)
{
	uint64_t attr = 32 * (intid / 32);
	uint64_t index = intid % 32;
	uint64_t val;
	int ret;

	ret = __kvm_device_attr_get(gic_fd, KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO,
				    attr, &val);
	if (ret != 0)
		return ret;

	val |= 1U << index;
	ret = __kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO,
				    attr, &val);
	return ret;
}

void kvm_irq_set_level_info(int gic_fd, uint32_t intid, int level)
{
	int ret = _kvm_irq_set_level_info(gic_fd, intid, level);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO, ret));
}

int _kvm_arm_irq_line(struct kvm_vm *vm, uint32_t intid, int level)
{
	uint32_t irq = intid & KVM_ARM_IRQ_NUM_MASK;

	TEST_ASSERT(!INTID_IS_SGI(intid), "KVM_IRQ_LINE's interface itself "
		"doesn't allow injecting SGIs. There's no mask for it.");

	if (INTID_IS_PPI(intid))
		irq |= KVM_ARM_IRQ_TYPE_PPI << KVM_ARM_IRQ_TYPE_SHIFT;
	else
		irq |= KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT;

	return _kvm_irq_line(vm, irq, level);
}

void kvm_arm_irq_line(struct kvm_vm *vm, uint32_t intid, int level)
{
	int ret = _kvm_arm_irq_line(vm, intid, level);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_IRQ_LINE, ret));
}

static void vgic_poke_irq(int gic_fd, uint32_t intid, struct kvm_vcpu *vcpu,
			  uint64_t reg_off)
{
	uint64_t reg = intid / 32;
	uint64_t index = intid % 32;
	uint64_t attr = reg_off + reg * 4;
	uint64_t val;
	bool intid_is_private = INTID_IS_SGI(intid) || INTID_IS_PPI(intid);

	uint32_t group = intid_is_private ? KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
					  : KVM_DEV_ARM_VGIC_GRP_DIST_REGS;

	if (intid_is_private) {
		/* TODO: only vcpu 0 implemented for now. */
		assert(vcpu->id == 0);
		attr += SZ_64K;
	}

	/* Check that the addr part of the attr is within 32 bits. */
	assert((attr & ~KVM_DEV_ARM_VGIC_OFFSET_MASK) == 0);

	/*
	 * All calls will succeed, even with invalid intid's, as long as the
	 * addr part of the attr is within 32 bits (checked above). An invalid
	 * intid will just make the read/writes point to above the intended
	 * register space (i.e., ICPENDR after ISPENDR).
	 */
	kvm_device_attr_get(gic_fd, group, attr, &val);
	val |= 1ULL << index;
	kvm_device_attr_set(gic_fd, group, attr, &val);
}

void kvm_irq_write_ispendr(int gic_fd, uint32_t intid, struct kvm_vcpu *vcpu)
{
	vgic_poke_irq(gic_fd, intid, vcpu, GICD_ISPENDR);
}

void kvm_irq_write_isactiver(int gic_fd, uint32_t intid, struct kvm_vcpu *vcpu)
{
	vgic_poke_irq(gic_fd, intid, vcpu, GICD_ISACTIVER);
}

#define VGIC_AFFINITY_0_SHIFT 0
#define VGIC_AFFINITY_1_SHIFT 8
#define VGIC_AFFINITY_2_SHIFT 16
#define VGIC_AFFINITY_3_SHIFT 24

#define MPIDR_TO_VGIC_LEVEL(mpidr, level) \
	((((mpidr) >> MPIDR_LEVEL_SHIFT(level)) & MPIDR_LEVEL_MASK) << \
	 VGIC_AFFINITY_## level ##_SHIFT)

#define MPIDR_TO_VGIC(mpidr) \
	((MPIDR_TO_VGIC_LEVEL(mpidr, 0) | \
	 MPIDR_TO_VGIC_LEVEL(mpidr, 1) | \
	 MPIDR_TO_VGIC_LEVEL(mpidr, 2) | \
	 MPIDR_TO_VGIC_LEVEL(mpidr, 3)) << 32)

static u32 vgic_rdist_read_reg(int gic_fd, struct kvm_vcpu *vcpu,
			       unsigned long offset)
{
	u64 mpidr, attr;
	u32 val;

	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_MPIDR_EL1), &mpidr);

	attr = MPIDR_TO_VGIC(mpidr) | offset;
	kvm_device_attr_get(gic_fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
			    attr, &val);

	return val;
}

static void vgic_rdist_write_reg(int gic_fd, struct kvm_vcpu *vcpu,
				 unsigned long offset, u32 val)
{
	u64 mpidr, attr;

	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_MPIDR_EL1), &mpidr);

	attr = MPIDR_TO_VGIC(mpidr) | offset;
	kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
			    attr, &val);
}

static void vgic_rdist_write_baser(int gic_fd, struct kvm_vcpu *vcpu,
				   unsigned long offset, u64 val)
{
	u32 attr = val;

	vgic_rdist_write_reg(gic_fd, vcpu, offset, attr);

	attr = val >> 32;
	vgic_rdist_write_reg(gic_fd, vcpu, offset + 4, attr);
}

void vgic_rdist_enable_lpis(int gic_fd, struct kvm_vcpu *vcpu,
			    vm_paddr_t cfg_table, size_t cfg_table_size,
			    vm_paddr_t pend_table)
{
	u32 ctlr;
	u64 val;

	val = (cfg_table |
	       GICR_PROPBASER_InnerShareable |
	       GICR_PROPBASER_RaWaWb |
	       ((ilog2(cfg_table_size) - 1) & GICR_PROPBASER_IDBITS_MASK));
	vgic_rdist_write_baser(gic_fd, vcpu, GICR_PROPBASER, val);

	val = (pend_table |
	       GICR_PENDBASER_InnerShareable |
	       GICR_PENDBASER_RaWaWb);
	vgic_rdist_write_baser(gic_fd, vcpu, GICR_PENDBASER, val);

	ctlr = vgic_rdist_read_reg(gic_fd, vcpu, GICR_CTLR);
	ctlr |= GICR_CTLR_ENABLE_LPIS;
	vgic_rdist_write_reg(gic_fd, vcpu, GICR_CTLR, ctlr);
}

static u64 vgic_its_read_reg(int its_fd, unsigned long offset)
{
	u64 attr;

	kvm_device_attr_get(its_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
			    offset, &attr);
	return attr;
}

static void vgic_its_write_reg(int its_fd, unsigned long offset, u64 val)
{
	kvm_device_attr_set(its_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
			    offset, &val);
}

static unsigned long vgic_its_find_baser(int its_fd, unsigned int type)
{
	int i;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		u64 baser;
		unsigned long offset = GITS_BASER + (i * sizeof(baser));

		baser = vgic_its_read_reg(its_fd, offset);
		if (GITS_BASER_TYPE(baser) == type)
			return offset;
	}

	TEST_FAIL("Couldn't find an ITS BASER of type %u", type);
	return -1;
}

static void vgic_its_install_table(int its_fd, unsigned int type, vm_paddr_t base,
				   size_t size)
{
	unsigned long offset = vgic_its_find_baser(its_fd, type);
	u64 baser;

	baser = ((size / SZ_64K) - 1) |
		GITS_BASER_PAGE_SIZE_64K |
		GITS_BASER_InnerShareable |
		base |
		GITS_BASER_RaWaWb |
		GITS_BASER_VALID;

	vgic_its_write_reg(its_fd, offset, baser);
}

static void vgic_its_install_cmdq(int its_fd, vm_paddr_t base, size_t size)
{
	u64 cbaser;

	cbaser = ((size / SZ_4K) - 1) |
		 GITS_CBASER_InnerShareable |
		 base |
		 GITS_CBASER_RaWaWb |
		 GITS_CBASER_VALID;

	vgic_its_write_reg(its_fd, GITS_CBASER, cbaser);
}

struct vgic_its *vgic_its_setup(struct kvm_vm *vm,
				vm_paddr_t coll_tbl, size_t coll_tbl_sz,
				vm_paddr_t device_tbl, size_t device_tbl_sz,
				vm_paddr_t cmdq, size_t cmdq_size)
{
	int its_fd = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_ITS);
	struct vgic_its *its = malloc(sizeof(struct vgic_its));
	u64 attr, ctlr;

	attr = GITS_BASE_GPA;
	kvm_device_attr_set(its_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
			    KVM_VGIC_ITS_ADDR_TYPE, &attr);

	kvm_device_attr_set(its_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
			    KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);

	vgic_its_install_table(its_fd, GITS_BASER_TYPE_COLLECTION, coll_tbl,
			       coll_tbl_sz);
	vgic_its_install_table(its_fd, GITS_BASER_TYPE_DEVICE, device_tbl,
			       device_tbl_sz);

	vgic_its_install_cmdq(its_fd, cmdq, cmdq_size);

	ctlr = vgic_its_read_reg(its_fd, GITS_CTLR);
	ctlr |= GITS_CTLR_ENABLE;
	vgic_its_write_reg(its_fd, GITS_CTLR, ctlr);

	*its = (struct vgic_its) {
		.its_fd		= its_fd,
		.cmdq_hva	= addr_gpa2hva(vm, cmdq),
		.cmdq_size	= cmdq_size,
	};

	return its;
}

void vgic_its_destroy(struct vgic_its *its)
{
	close(its->its_fd);
	free(its);
}

struct its_cmd_block {
	union {
		u64	raw_cmd[4];
		__le64	raw_cmd_le[4];
	};
};

static inline void its_fixup_cmd(struct its_cmd_block *cmd)
{
	/* Let's fixup BE commands */
	cmd->raw_cmd_le[0] = cpu_to_le64(cmd->raw_cmd[0]);
	cmd->raw_cmd_le[1] = cpu_to_le64(cmd->raw_cmd[1]);
	cmd->raw_cmd_le[2] = cpu_to_le64(cmd->raw_cmd[2]);
	cmd->raw_cmd_le[3] = cpu_to_le64(cmd->raw_cmd[3]);
}

static void its_mask_encode(u64 *raw_cmd, u64 val, int h, int l)
{
	u64 mask = GENMASK_ULL(h, l);
	*raw_cmd &= ~mask;
	*raw_cmd |= (val << l) & mask;
}

static void its_encode_cmd(struct its_cmd_block *cmd, u8 cmd_nr)
{
	its_mask_encode(&cmd->raw_cmd[0], cmd_nr, 7, 0);
}

static void its_encode_devid(struct its_cmd_block *cmd, u32 devid)
{
	its_mask_encode(&cmd->raw_cmd[0], devid, 63, 32);
}

static void its_encode_event_id(struct its_cmd_block *cmd, u32 id)
{
	its_mask_encode(&cmd->raw_cmd[1], id, 31, 0);
}

static void its_encode_phys_id(struct its_cmd_block *cmd, u32 phys_id)
{
	its_mask_encode(&cmd->raw_cmd[1], phys_id, 63, 32);
}

static void its_encode_size(struct its_cmd_block *cmd, u8 size)
{
	its_mask_encode(&cmd->raw_cmd[1], size, 4, 0);
}

static void its_encode_itt(struct its_cmd_block *cmd, u64 itt_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], itt_addr >> 8, 51, 8);
}

static void its_encode_valid(struct its_cmd_block *cmd, int valid)
{
	its_mask_encode(&cmd->raw_cmd[2], !!valid, 63, 63);
}

static void its_encode_target(struct its_cmd_block *cmd, u64 target_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], target_addr >> 16, 51, 16);
}

static void its_encode_collection(struct its_cmd_block *cmd, u16 col)
{
	its_mask_encode(&cmd->raw_cmd[2], col, 15, 0);
}

static void vgic_its_send_cmd(struct vgic_its *its, struct its_cmd_block *cmd)
{
	u64 cwriter = vgic_its_read_reg(its->its_fd, GITS_CWRITER);
	struct its_cmd_block *dst = its->cmdq_hva + cwriter;
	u64 next;

	its_fixup_cmd(cmd);

	WRITE_ONCE(*dst, *cmd);
	dsb(ishst);

	next = (cwriter + sizeof(*cmd)) % its->cmdq_size;
	vgic_its_write_reg(its->its_fd, GITS_CWRITER, next);

	TEST_ASSERT(vgic_its_read_reg(its->its_fd, GITS_CREADR) == next,
		    "ITS didn't process command at offset: %lu\n", cwriter);
}

void vgic_its_send_mapd_cmd(struct vgic_its *its, u32 device_id,
		            vm_paddr_t itt_base, size_t itt_size, bool valid)
{
	struct its_cmd_block cmd = {};

	its_encode_cmd(&cmd, GITS_CMD_MAPD);
	its_encode_devid(&cmd, device_id);
	its_encode_size(&cmd, ilog2(itt_size) - 1);
	its_encode_itt(&cmd, itt_base);
	its_encode_valid(&cmd, valid);

	vgic_its_send_cmd(its, &cmd);
}

void vgic_its_send_mapc_cmd(struct vgic_its *its, struct kvm_vcpu *vcpu,
			    u32 collection_id, bool valid)
{
	struct its_cmd_block cmd = {};

	its_encode_cmd(&cmd, GITS_CMD_MAPC);
	its_encode_collection(&cmd, collection_id);
	its_encode_target(&cmd, vcpu->id);
	its_encode_valid(&cmd, valid);

	vgic_its_send_cmd(its, &cmd);
}

void vgic_its_send_mapti_cmd(struct vgic_its *its, u32 device_id,
			     u32 event_id, u32 collection_id, u32 intid)
{
	struct its_cmd_block cmd = {};

	its_encode_cmd(&cmd, GITS_CMD_MAPTI);
	its_encode_devid(&cmd, device_id);
	its_encode_event_id(&cmd, event_id);
	its_encode_phys_id(&cmd, intid);
	its_encode_collection(&cmd, collection_id);

	vgic_its_send_cmd(its, &cmd);
}

void vgic_its_send_invall_cmd(struct vgic_its *its, u32 collection_id)
{
	struct its_cmd_block cmd = {};

	its_encode_cmd(&cmd, GITS_CMD_INVALL);
	its_encode_collection(&cmd, collection_id);

	vgic_its_send_cmd(its, &cmd);
}
