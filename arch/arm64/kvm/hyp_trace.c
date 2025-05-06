// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Google LLC
 * Author: Vincent Donnefort <vdonnefort@google.com>
 */

#include <linux/trace_remote.h>
#include <linux/simple_ring_buffer.h>

#include <asm/kvm_host.h>
#include <asm/kvm_hyptrace.h>

#include "hyp_trace.h"

/* Access to this struct within the trace_remote_callbacks are protected by the trace_remote lock */
struct hyp_trace_buffer {
	struct hyp_trace_desc	*desc;
	size_t			desc_size;
} trace_buffer;

static int hyp_trace_buffer_alloc_bpages_backing(struct hyp_trace_buffer *trace_buffer, size_t size)
{
	int nr_bpages = (PAGE_ALIGN(size) / PAGE_SIZE) + 1;
	size_t backing_size;
	void *start;

	backing_size = PAGE_ALIGN(sizeof(struct simple_buffer_page) * nr_bpages *
				  num_possible_cpus());

	start = alloc_pages_exact(backing_size, GFP_KERNEL_ACCOUNT);
	if (!start)
		return -ENOMEM;

	trace_buffer->desc->bpages_backing_start = (unsigned long)start;
	trace_buffer->desc->bpages_backing_size = backing_size;

	return 0;
}

static void hyp_trace_buffer_free_bpages_backing(struct hyp_trace_buffer *trace_buffer)
{
	free_pages_exact((void *)trace_buffer->desc->bpages_backing_start,
			 trace_buffer->desc->bpages_backing_size);
}

static int __load_page(unsigned long va)
{
	return kvm_call_hyp_nvhe(__pkvm_host_share_hyp, virt_to_pfn((void *)va), 1);
}

static void __unload_page(unsigned long va)
{
	WARN_ON(kvm_call_hyp_nvhe(__pkvm_host_unshare_hyp, virt_to_pfn((void *)va), 1));
}

static void hyp_trace_buffer_unload_pages(struct hyp_trace_buffer *trace_buffer, int last_cpu)
{
	struct ring_buffer_desc *rb_desc;
	int cpu, p;

	for_each_ring_buffer_desc(rb_desc, cpu, &trace_buffer->desc->trace_buffer_desc) {
		if (cpu > last_cpu)
			break;

		__unload_page(rb_desc->meta_va);
		for (p = 0; p < rb_desc->nr_page_va; p++)
			__unload_page(rb_desc->page_va[p]);
	}
}

static int hyp_trace_buffer_load_pages(struct hyp_trace_buffer *trace_buffer)
{
	struct ring_buffer_desc *rb_desc;
	int cpu, p, ret = 0;

	for_each_ring_buffer_desc(rb_desc, cpu, &trace_buffer->desc->trace_buffer_desc) {
		ret = __load_page(rb_desc->meta_va);
		if (ret)
			break;

		for (p = 0; p < rb_desc->nr_page_va; p++) {
			ret = __load_page(rb_desc->page_va[p]);
			if (ret)
				break;
		}

		if (ret) {
			for (p--; p >= 0; p--)
				__unload_page(rb_desc->page_va[p]);
			break;
		}
	}

	if (ret)
		hyp_trace_buffer_unload_pages(trace_buffer, cpu--);

	return ret;
}

static struct trace_buffer_desc *hyp_trace_load(unsigned long size, void *priv)
{
	struct hyp_trace_buffer *trace_buffer = priv;
	struct hyp_trace_desc *desc;
	size_t desc_size;
	int ret;

	if (WARN_ON(trace_buffer->desc))
		return NULL;

	desc_size = trace_buffer_desc_size(size, num_possible_cpus());
	if (desc_size == SIZE_MAX)
		return NULL;

	/*
	 * The hypervisor will unmap the descriptor from the host to protect the reading. Page
	 * granularity for the allocation ensures no other useful data will be unmapped.
	 */
	desc_size = PAGE_ALIGN(desc_size);
	desc = (struct hyp_trace_desc *)alloc_pages_exact(desc_size, GFP_KERNEL);
	if (!desc)
		return NULL;

	trace_buffer->desc = desc;

	ret = hyp_trace_buffer_alloc_bpages_backing(trace_buffer, size);
	if (ret)
		goto err_free_desc;

	ret = trace_remote_alloc_buffer(&desc->trace_buffer_desc, size, cpu_possible_mask);
	if (ret)
		goto err_free_backing;

	ret = hyp_trace_buffer_load_pages(trace_buffer);
	if (ret)
		goto err_free_buffer;

	ret = kvm_call_hyp_nvhe(__pkvm_load_tracing, (unsigned long)desc, desc_size);
	if (ret)
		goto err_unload_pages;

	return &desc->trace_buffer_desc;

err_unload_pages:
	hyp_trace_buffer_unload_pages(trace_buffer, INT_MAX);

err_free_buffer:
	trace_remote_free_buffer(&desc->trace_buffer_desc);

err_free_backing:
	hyp_trace_buffer_free_bpages_backing(trace_buffer);

err_free_desc:
	free_pages_exact(desc, desc_size);
	trace_buffer->desc = NULL;

	return NULL;
}

static void hyp_trace_unload(struct trace_buffer_desc *desc, void *priv)
{
	struct hyp_trace_buffer *trace_buffer = priv;

	if (WARN_ON(desc != &trace_buffer->desc->trace_buffer_desc))
		return;

	kvm_call_hyp_nvhe(__pkvm_unload_tracing);
	hyp_trace_buffer_unload_pages(trace_buffer, INT_MAX);
	trace_remote_free_buffer(desc);
	hyp_trace_buffer_free_bpages_backing(trace_buffer);
	free_pages_exact(trace_buffer->desc, trace_buffer->desc_size);
	trace_buffer->desc = NULL;
}

static int hyp_trace_enable_tracing(bool enable, void *priv)
{
	return kvm_call_hyp_nvhe(__pkvm_enable_tracing, enable);
}

static int hyp_trace_swap_reader_page(unsigned int cpu, void *priv)
{
	return kvm_call_hyp_nvhe(__pkvm_swap_reader_tracing, cpu);
}

static int hyp_trace_reset(unsigned int cpu, void *priv)
{
	return 0;
}

static int hyp_trace_enable_event(unsigned short id, bool enable, void *priv)
{
	return 0;
}

static struct trace_remote_callbacks trace_remote_callbacks = {
	.load_trace_buffer	= hyp_trace_load,
	.unload_trace_buffer	= hyp_trace_unload,
	.enable_tracing		= hyp_trace_enable_tracing,
	.swap_reader_page	= hyp_trace_swap_reader_page,
	.reset			= hyp_trace_reset,
	.enable_event		= hyp_trace_enable_event,
};

int hyp_trace_init(void)
{
	if (!is_protected_kvm_enabled())
		return 0;

	return trace_remote_register("hypervisor", &trace_remote_callbacks, &trace_buffer, NULL, 0);
}
