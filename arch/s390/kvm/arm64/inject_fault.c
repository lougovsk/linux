// SPDX-License-Identifier: GPL-2.0

#include <asm/kvm_emulate.h>

/**
 * kvm_inject_undefined - inject an undefined instruction into the guest
 * @vcpu: The vCPU in which to inject the exception
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_undefined(struct kvm_vcpu *vcpu)
{
	/* Stub until s390 supports arm64 sysregs TODO sysregs*/
}
