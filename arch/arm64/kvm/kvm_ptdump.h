// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Google, 2023
 * Author: Sebastian Ene <sebastianene@google.com>
 */

#ifndef __KVM_PTDUMP_H
#define __KVM_PTDUMP_H

#include <linux/kvm_host.h>
#include <asm/ptdump.h>


#ifdef CONFIG_PTDUMP_STAGE2_DEBUGFS
int kvm_ptdump_guest_register(struct kvm *kvm);
#else
static inline int kvm_ptdump_guest_register(struct kvm *kvm) { return 0; }
#endif /* CONFIG_PTDUMP_STAGE2_DEBUGFS */

#endif /* __KVM_PTDUMP_H */
