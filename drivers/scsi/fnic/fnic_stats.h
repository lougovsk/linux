/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2013 Cisco Systems, Inc.  All rights reserved. */
#ifndef _FNIC_STATS_H_
#define _FNIC_STATS_H_
#define FNIC_MQ_MAX_QUEUES 64
#include <scsi/scsi_transport_fc.h>

struct stats_timestamps {
	struct timespec64 last_reset_time;
	struct timespec64 last_read_time;
};

struct io_path_stats {
	atomic64_t active_ios;
	atomic64_t max_active_ios;
	atomic64_t io_completions;
	atomic64_t io_failures;
	atomic64_t ioreq_null;
	atomic64_t alloc_failures;
	atomic64_t sc_null;
	atomic64_t io_not_found;
	atomic64_t num_ios;
	atomic64_t io_btw_0_to_10_msec;
	atomic64_t io_btw_10_to_100_msec;
	atomic64_t io_btw_100_to_500_msec;
	atomic64_t io_btw_500_to_5000_msec;
	atomic64_t io_btw_5000_to_10000_msec;
	atomic64_t io_btw_10000_to_30000_msec;
	atomic64_t io_greater_than_30000_msec;
	atomic64_t current_max_io_time;
	atomic64_t ios[FNIC_MQ_MAX_QUEUES];
};

struct abort_stats {
	atomic64_t aborts;
	atomic64_t abort_failures;
	atomic64_t abort_drv_timeouts;
	atomic64_t abort_fw_timeouts;
	atomic64_t abort_io_not_found;
	atomic64_t abort_issued_btw_0_to_6_sec;
	atomic64_t abort_issued_btw_6_to_20_sec;
	atomic64_t abort_issued_btw_20_to_30_sec;
	atomic64_t abort_issued_btw_30_to_40_sec;
	atomic64_t abort_issued_btw_40_to_50_sec;
	atomic64_t abort_issued_btw_50_to_60_sec;
	atomic64_t abort_issued_greater_than_60_sec;
};

struct terminate_stats {
	atomic64_t terminates;
	atomic64_t max_terminates;
	atomic64_t terminate_drv_timeouts;
	atomic64_t terminate_fw_timeouts;
	atomic64_t terminate_io_not_found;
	atomic64_t terminate_failures;
};

struct reset_stats {
	atomic64_t device_resets;
	atomic64_t device_reset_failures;
	atomic64_t device_reset_aborts;
	atomic64_t device_reset_timeouts;
	atomic64_t device_reset_terminates;
	atomic64_t fw_resets;
	atomic64_t fw_reset_completions;
	atomic64_t fw_reset_failures;
	atomic64_t fw_reset_timeouts;
	atomic64_t fnic_resets;
	atomic64_t fnic_reset_completions;
	atomic64_t fnic_reset_failures;
};

struct fw_stats {
	atomic64_t active_fw_reqs;
	atomic64_t max_fw_reqs;
	atomic64_t fw_out_of_resources;
	atomic64_t io_fw_errs;
};

struct vlan_stats {
	atomic64_t vlan_disc_reqs;
	atomic64_t resp_withno_vlanID;
	atomic64_t sol_expiry_count;
	atomic64_t flogi_rejects;
};

struct misc_stats {
	u64 last_isr_time;
	u64 last_ack_time;
	atomic64_t max_isr_jiffies;
	atomic64_t max_isr_time_ms;
	atomic64_t corr_work_done;
	atomic64_t isr_count;
	atomic64_t max_cq_entries;
	atomic64_t ack_index_out_of_range;
	atomic64_t data_count_mismatch;
	atomic64_t fcpio_timeout;
	atomic64_t fcpio_aborted;
	atomic64_t sgl_invalid;
	atomic64_t mss_invalid;
	atomic64_t abts_cpwq_alloc_failures;
	atomic64_t devrst_cpwq_alloc_failures;
	atomic64_t io_cpwq_alloc_failures;
	atomic64_t no_icmnd_itmf_cmpls;
	atomic64_t check_condition;
	atomic64_t queue_fulls;
	atomic64_t tport_not_ready;
	atomic64_t iport_not_ready;
	atomic64_t frame_errors;
	atomic64_t current_port_speed;
	atomic64_t intx_dummy;
	atomic64_t port_speed_in_mbps;
};

struct fnic_iport_stats {
	atomic64_t num_linkdn;
	atomic64_t num_linkup;
	atomic64_t link_failure_count;
	atomic64_t num_rscns;
	atomic64_t rscn_redisc;
	atomic64_t rscn_not_redisc;
	atomic64_t frame_err;
	atomic64_t num_rnid;
	atomic64_t fabric_flogi_sent;
	atomic64_t fabric_flogi_ls_accepts;
	atomic64_t fabric_flogi_ls_rejects;
	atomic64_t fabric_flogi_misc_rejects;
	atomic64_t fabric_plogi_sent;
	atomic64_t fabric_plogi_ls_accepts;
	atomic64_t fabric_plogi_ls_rejects;
	atomic64_t fabric_plogi_misc_rejects;
	atomic64_t fabric_scr_sent;
	atomic64_t fabric_scr_ls_accepts;
	atomic64_t fabric_scr_ls_rejects;
	atomic64_t fabric_scr_misc_rejects;
	atomic64_t fabric_logo_sent;
	atomic64_t tport_alive;
	atomic64_t tport_plogi_sent;
	atomic64_t tport_plogi_ls_accepts;
	atomic64_t tport_plogi_ls_rejects;
	atomic64_t tport_plogi_misc_rejects;
	atomic64_t tport_prli_sent;
	atomic64_t tport_prli_ls_accepts;
	atomic64_t tport_prli_ls_rejects;
	atomic64_t tport_prli_misc_rejects;
	atomic64_t tport_adisc_sent;
	atomic64_t tport_adisc_ls_accepts;
	atomic64_t tport_adisc_ls_rejects;
	atomic64_t tport_logo_sent;
	atomic64_t unsupported_frames_ls_rejects;
	atomic64_t unsupported_frames_dropped;
};

struct fnic_stats {
	struct stats_timestamps stats_timestamps;
	struct io_path_stats io_stats;
	struct abort_stats abts_stats;
	struct terminate_stats term_stats;
	struct reset_stats reset_stats;
	struct fw_stats fw_stats;
	struct vlan_stats vlan_stats;
	struct fc_host_statistics host_stats;
	struct misc_stats misc_stats;
};

struct stats_debug_info {
	char *debug_buffer;
	void *i_private;
	int buf_size;
	int buffer_len;
};

int fnic_get_stats_data(struct stats_debug_info *, struct fnic_stats *);
const char *fnic_role_to_str(unsigned int role);
#endif /* _FNIC_STATS_H_ */
