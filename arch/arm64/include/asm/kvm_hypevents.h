/* SPDX-License-Identifier: GPL-2.0 */

#if !defined(__ARM64_KVM_HYPEVENTS_H_) || defined(HYP_EVENT_MULTI_READ)
#define __ARM64_KVM_HYPEVENTS_H_

#ifdef __KVM_NVHE_HYPERVISOR__
#include <nvhe/trace.h>
#endif

#ifndef __HYP_ENTER_EXIT_REASON
#define __HYP_ENTER_EXIT_REASON
enum hyp_enter_exit_reason {
	HYP_REASON_SMC,
	HYP_REASON_HVC,
	HYP_REASON_PSCI,
	HYP_REASON_HOST_ABORT,
	HYP_REASON_GUEST_EXIT,
	HYP_REASON_ERET_HOST,
	HYP_REASON_ERET_GUEST,
	HYP_REASON_UNKNOWN	/* Must be last */
};
#endif

HYP_EVENT(hyp_enter,
	HE_PROTO(u8 reason),
	HE_STRUCT(
		he_field(u8, reason)
	),
	HE_ASSIGN(
		__entry->reason = reason;
	),
	HE_PRINTK("reason=%s", __hyp_enter_exit_reason_str(__entry->reason))
);

HYP_EVENT(hyp_exit,
	HE_PROTO(u8 reason),
	HE_STRUCT(
		he_field(u8, reason)
	),
	HE_ASSIGN(
		__entry->reason = reason;
	),
	HE_PRINTK("reason=%s", __hyp_enter_exit_reason_str(__entry->reason))
);

HYP_EVENT(selftest,
	HE_PROTO(u64 id),
	HE_STRUCT(
		he_field(u64, id)
	),
	HE_ASSIGN(
		__entry->id = id;
	),
	RE_PRINTK("id=%llu", __entry->id)
);
#endif
