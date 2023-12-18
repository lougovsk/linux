/* SPDX-License-Identifier: GPL-2.0-only */
//
// Copyright (C) Google, 2023
// Author: Sebastian Ene <sebastianene@google.com>

#ifndef __KVM_PTDUMP_H
#define __KVM_PTDUMP_H

#include <asm/ptdump.h>


#ifdef CONFIG_PTDUMP_STAGE2_DEBUGFS
void kvm_ptdump_register_host(void);
#else
static inline void kvm_ptdump_register_host(void) { }
#endif /* CONFIG_PTDUMP_STAGE2_DEBUGFS */

#endif /* __KVM_PTDUMP_H */
