/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_VGIC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VGIC_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(vgic_update_irq_pending,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, bool level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_id	)
		__field(	__u32,		irq	)
		__field(	bool,		level	)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %ld, IRQ %d, level: %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

DECLARE_EVENT_CLASS(vgic_its_cmd_class,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id),

	TP_STRUCT__entry(
		__field(	__u32,		device_id		)
		__field(	__u32,		event_id		)
	),

	TP_fast_assign(
		__entry->device_id		= device_id;
		__entry->event_id		= event_id;
	),

	TP_printk("Device ID: %u, Event ID: %u",
		  __entry->device_id, __entry->event_id)
);

DEFINE_EVENT(vgic_its_cmd_class, vgic_its_cmd_mapi,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id));

DEFINE_EVENT(vgic_its_cmd_class, vgic_its_cmd_discard,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id));

DEFINE_EVENT(vgic_its_cmd_class, vgic_its_cmd_clear,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id));

DEFINE_EVENT(vgic_its_cmd_class, vgic_its_cmd_int,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id));

DEFINE_EVENT(vgic_its_cmd_class, vgic_its_cmd_inv,
	TP_PROTO(__u32 device_id, __u32 event_id),
	TP_ARGS(device_id, event_id));

TRACE_EVENT(vgic_its_cmd_mapd,
	TP_PROTO(__u32 device_id, bool valid, __u8 num_eventid_bits, __u64 itt_addr),
	TP_ARGS(device_id, valid, num_eventid_bits, itt_addr),

	TP_STRUCT__entry(
		__field(	__u32,		device_id		)
		__field(	bool,		valid			)
		__field(	__u8,		num_eventid_bits	)
		__field(	__u64,		itt_addr		)
	),

	TP_fast_assign(
		__entry->device_id		= device_id;
		__entry->valid			= valid;
		__entry->num_eventid_bits	= num_eventid_bits;
		__entry->itt_addr		= itt_addr;
	),

	TP_printk("Device ID: %u, valid: %d, num_eventid_bits: %u, itt_addr: %llx",
		  __entry->device_id, __entry->valid,
		  __entry->num_eventid_bits, __entry->itt_addr)
);

TRACE_EVENT(vgic_its_cmd_mapc,
	TP_PROTO(__u32 collection_id, bool valid),
	TP_ARGS(collection_id, valid),

	TP_STRUCT__entry(
		__field(	__u32,		collection_id		)
		__field(	bool,		valid			)
	),

	TP_fast_assign(
		__entry->collection_id		= collection_id;
		__entry->valid			= valid;
	),

	TP_printk("Collection ID: %u, valid: %d",
		  __entry->collection_id, __entry->valid)
);

TRACE_EVENT(vgic_its_cmd_movi,
	TP_PROTO(__u32 device_id, __u32 event_id, __u32 collection_id),
	TP_ARGS(device_id, event_id, collection_id),

	TP_STRUCT__entry(
		__field(	__u32,		device_id		)
		__field(	__u32,		event_id		)
		__field(	__u32,		collection_id		)
	),

	TP_fast_assign(
		__entry->device_id		= device_id;
		__entry->event_id		= event_id;
		__entry->collection_id		= collection_id;
	),

	TP_printk("Device ID: %u, Event ID: %u, Collection ID: %u",
		  __entry->device_id, __entry->event_id, __entry->collection_id)
);

TRACE_EVENT(vgic_its_cmd_movall,
	TP_PROTO(int vcpu_source, int vcpu_target),
	TP_ARGS(vcpu_source, vcpu_target),

	TP_STRUCT__entry(
		__field(	int,		vcpu_source		)
		__field(	int,		vcpu_target		)
	),

	TP_fast_assign(
		__entry->vcpu_source		= vcpu_source;
		__entry->vcpu_target		= vcpu_target;
	),

	TP_printk("Source VCPU: %d, Target VCPU: %d",
		  __entry->vcpu_source, __entry->vcpu_target)
);

TRACE_EVENT(vgic_its_cmd_invall,
	TP_PROTO(__u32 collection_id, int vcpu_id),
	TP_ARGS(collection_id, vcpu_id),

	TP_STRUCT__entry(
		__field(	__u32,		collection_id		)
		__field(	int,		vcpu_id			)
	),

	TP_fast_assign(
		__entry->collection_id		= collection_id;
		__entry->vcpu_id		= vcpu_id;
	),

	TP_printk("Collection ID: %u, VCPU ID: %d",
		  __entry->collection_id, __entry->vcpu_id)
);

#endif /* _TRACE_VGIC_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/arm64/kvm/vgic
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
