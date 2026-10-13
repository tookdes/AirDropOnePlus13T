/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OP13T_WONDERTAP_MIN_H
#define OP13T_WONDERTAP_MIN_H
/*
 * Minimal vendor ops/priv layout matching the pinned 13T Wonder headers.
 * Used only by the optional software stub. Not a radio implementation.
 */
#ifndef OP13T_SYNTAX_SMOKE_ONLY
#include <linux/types.h>
#else
typedef unsigned int u32;
typedef unsigned char u8;
#endif

struct wondertap_set_freq_params;
struct wondertap_deinit_params;
struct wondertap_fixed_tx_rate_params;
struct wondertap_tx_rate_mask_params;
enum wondertap_filter_type { WONDERTAP_FILTER_TYPE_FRAME = 0 };

struct wondertap_capability {
	u32 version;
	union {
		u32 raw_bits;
		struct {
			u32 rate_adaptation: 1;
			u32 sta_coexist: 1;
			u32 sap_coexist: 1;
			u32 p2p_coexist: 1;
			u32 nan_coexist: 1;
			u32 ranging_coexist: 1;
			u32 amsdu_aggregation: 1;
			u32 ampdu_aggregation: 1;
			u32 dynamic_freq: 1;
			u32 dynamic_fixed_tx_rate: 1;
			u32 custom_mgmt_retry_limit: 1;
			u32 custom_data_retry_limit: 1;
			u32 frame_type_filter: 1;
			u32 reserved: 19;
		} bits;
	};
};

struct wondertap_init_params;

struct wondertap_ops {
	int (*init)(void **handle, const struct wondertap_init_params *params);
	void (*deinit)(void *handle, const struct wondertap_deinit_params *params);
	int (*set_freq)(void *handle, const struct wondertap_set_freq_params *params);
	int (*set_filter)(void *handle, enum wondertap_filter_type filter_type,
			  const void *params);
	int (*set_fixed_tx_rate)(void *handle,
				 const struct wondertap_fixed_tx_rate_params *params);
	int (*set_tx_rate_mask)(void *handle,
				const struct wondertap_tx_rate_mask_params *params);
	int (*get_capabilities)(void *handle, struct wondertap_capability *features);
};

enum wondertap_ver {
	WONDER_VERSION_1_0,
	WONDER_VERSION_1_1,
	WONDER_VERSION_1_2,
	WONDER_VERSION_1_3,
	WONDER_VERSION_1_4,
	WONDER_VERSION_1_4_1,
	WONDER_VERSION_1_5,
	WONDER_VERSION_1_5_1,
	WONDER_VERSION_MAX,
};

struct wondertap_priv {
	enum wondertap_ver ver;
	const struct wondertap_ops *wonder_ops;
};

#endif
