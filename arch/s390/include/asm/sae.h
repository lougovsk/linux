/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_S390_SAE_H
#define __ASM_S390_SAE_H

/* defined in arch/s390/kernel/entry.S */
int __sae64a(phys_addr_t sae_block_phys);

/**
 * __sae64a() - Start Arm Execution
 */
static inline void sae64a(struct kvm_sae_block *sae_block)
{
	__sae64a(virt_to_phys(sae_block));
}

/**
 * stiasrm() - STore and Invalidate Arm System Register Multiple
 */
static __always_inline void stiasrm(struct kvm_sae_save_area *save_area)
{
	asm volatile(".insn	rre,0xb9a70000,%[r1],0\n"
		     : "=m"(*save_area)
		     : [r1] "d"(save_area));
}

/**
 * lasrm() - Load Arm System Register Multiple
 *
 */
static __always_inline void lasrm(struct kvm_sae_save_area *save_area)
{
	asm volatile(".insn	rre,0xb9a60000,%[r1],0\n"
		     :
		     : "m" (*save_area),
		      [r1] "d" (save_area)
	);
}

#endif /* __ASM_S390_SAE_H */
