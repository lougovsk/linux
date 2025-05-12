// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Ampere Computing LLC
 */

#include <linux/compiler.h>
#include <assert.h>

#include "guest_modes.h"
#include "kvm_util.h"
#include "nv_util.h"
#include "processor.h"

struct kvm_vm *__nv_vm_create_with_vcpus_gic(struct vm_shape shape, uint32_t nr_vcpus,
		struct kvm_vcpu **vcpus, uint64_t extra_mem_pages, int *gic_fd, void *guest_code)
{
	struct kvm_vcpu_init init;
	struct kvm_vm *vm;
	int i;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_ARM_EL2));

	vm = __vm_create(shape, nr_vcpus, extra_mem_pages);
	vm_ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init);
	init_vcpu_nested(&init);

	for (i = 0; i < nr_vcpus; ++i) {
		vcpus[i] = aarch64_vcpu_add(vm, i, &init, guest_code);
		__TEST_REQUIRE(is_vcpu_nested(vcpus[i]), "Failed to Enable NV");
	}

	/* vgic is not created, If gic_fd argument is NULL */
	if (gic_fd) {
		*gic_fd = vgic_v3_setup(vm, nr_vcpus, 64);
		__TEST_REQUIRE(*gic_fd >= 0, "Failed to create vgic-v3");
	}

	return vm;
}

struct kvm_vm *nv_vm_create_with_vcpus_gic(uint32_t nr_vcpus,
		struct kvm_vcpu **vcpus, int *gic_fd, void *guest_code)
{
	return __nv_vm_create_with_vcpus_gic(VM_SHAPE_DEFAULT,
				nr_vcpus, vcpus, 0, gic_fd, guest_code);
}
