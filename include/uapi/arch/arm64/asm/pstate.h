/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI__ASM_PSTATE_H
#define _UAPI__ASM_PSTATE_H

/*
 * PSR bits
 */
#define PSR_MODE_EL0t  0x00000000
#define PSR_MODE_EL1t  0x00000004
#define PSR_MODE_EL1h  0x00000005
#define PSR_MODE_EL2t  0x00000008
#define PSR_MODE_EL2h  0x00000009
#define PSR_MODE_EL3t  0x0000000c
#define PSR_MODE_EL3h  0x0000000d
#define PSR_MODE_MASK  0x0000000f

/* AArch32 CPSR bits */
#define PSR_MODE32_BIT         0x00000010

/* AArch64 SPSR bits */
#define PSR_F_BIT      0x00000040
#define PSR_I_BIT      0x00000080
#define PSR_A_BIT      0x00000100
#define PSR_D_BIT      0x00000200
#define PSR_BTYPE_MASK 0x00000c00
#define PSR_SSBS_BIT   0x00001000
#define PSR_PAN_BIT    0x00400000
#define PSR_UAO_BIT    0x00800000
#define PSR_DIT_BIT    0x01000000
#define PSR_TCO_BIT    0x02000000
#define PSR_V_BIT      0x10000000
#define PSR_C_BIT      0x20000000
#define PSR_Z_BIT      0x40000000
#define PSR_N_BIT      0x80000000

#define PSR_BTYPE_SHIFT                10

/*
 * Groups of PSR bits
 */
#define PSR_f          0xff000000      /* Flags                */
#define PSR_s          0x00ff0000      /* Status               */
#define PSR_x          0x0000ff00      /* Extension            */
#define PSR_c          0x000000ff      /* Control              */

/* Convenience names for the values of PSTATE.BTYPE */
#define PSR_BTYPE_NONE         (0b00 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_JC           (0b01 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_C            (0b10 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_J            (0b11 << PSR_BTYPE_SHIFT)

#endif /* _UAPI__ASM_PSTATE_H */
