/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2020, The Linux Foundation. All rights reserved.
 */

#ifndef _DP_AUDIO_H_
#define _DP_AUDIO_H_

#include <linux/platform_device.h>

#include "dp_catalog.h"
#include <sound/hdmi-codec.h>

/**
 * struct msm_dp_audio
 * @lane_count: number of lanes configured in current session
 * @bw_code: link rate's bandwidth code for current session
 */
struct msm_dp_audio {
	u32 lane_count;
	u32 bw_code;
};

/**
 * msm_dp_audio_get()
 *
 * Creates and instance of dp audio.
 *
 * @pdev: caller's platform device instance.
 * @catalog: an instance of msm_dp_catalog module.
 *
 * Returns the error code in case of failure, otherwize
 * an instance of newly created msm_dp_module.
 */
struct msm_dp_audio *msm_dp_audio_get(struct platform_device *pdev,
			struct msm_dp_catalog *catalog);

/**
 * msm_dp_audio_put()
 *
 * Cleans the msm_dp_audio instance.
 *
 * @msm_dp_audio: an instance of msm_dp_audio.
 */
void msm_dp_audio_put(struct msm_dp_audio *msm_dp_audio);

int msm_dp_audio_prepare(struct drm_connector *connector,
			 struct drm_bridge *bridge,
			 struct hdmi_codec_daifmt *daifmt,
			 struct hdmi_codec_params *params);
void msm_dp_audio_shutdown(struct drm_connector *connector,
			   struct drm_bridge *bridge);

#endif /* _DP_AUDIO_H_ */


