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

TRACE_EVENT(vgic_its_trans_cache_hit,
	TP_PROTO(__u64 db_addr, __u32 device_id, __u32 event_id, __u32 intid),
	TP_ARGS(db_addr, device_id, event_id, intid),

	TP_STRUCT__entry(
		__field(	__u64,		db_addr		)
		__field(	__u32,		device_id	)
		__field(	__u32,		event_id	)
		__field(	__u32,		intid		)
	),

	TP_fast_assign(
		__entry->db_addr	= db_addr;
		__entry->device_id	= device_id;
		__entry->event_id	= event_id;
		__entry->intid		= intid;
	),

	TP_printk("DB: %016llx, device_id %u, event_id %u, intid %u",
                  __entry->db_addr, __entry->device_id, __entry->event_id,
                  __entry->intid)
);

TRACE_EVENT(vgic_its_trans_cache_miss,
	TP_PROTO(__u64 db_addr, __u32 device_id, __u32 event_id),
	TP_ARGS(db_addr, device_id, event_id),

	TP_STRUCT__entry(
		__field(	__u64,		db_addr		)
		__field(	__u32,		device_id	)
		__field(	__u32,		event_id	)
	),

	TP_fast_assign(
		__entry->db_addr	= db_addr;
		__entry->device_id	= device_id;
		__entry->event_id	= event_id;
	),

	TP_printk("DB: %016llx, device_id %u, event_id %u",
                  __entry->db_addr, __entry->device_id, __entry->event_id)
);

TRACE_EVENT(vgic_its_trans_cache_victim,
	TP_PROTO(__u64 db_addr, __u32 device_id, __u32 event_id, __u32 intid),
	TP_ARGS(db_addr, device_id, event_id, intid),

	TP_STRUCT__entry(
		__field(	__u64,		db_addr		)
		__field(	__u32,		device_id	)
		__field(	__u32,		event_id	)
		__field(	__u32,		intid		)
	),

	TP_fast_assign(
		__entry->db_addr	= db_addr;
		__entry->device_id	= device_id;
		__entry->event_id	= event_id;
		__entry->intid		= intid;
	),

	TP_printk("DB: %016llx, device_id %u, event_id %u, intid %u",
                  __entry->db_addr, __entry->device_id, __entry->event_id,
                  __entry->intid)
);

#endif /* _TRACE_VGIC_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/arm64/kvm/vgic
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
