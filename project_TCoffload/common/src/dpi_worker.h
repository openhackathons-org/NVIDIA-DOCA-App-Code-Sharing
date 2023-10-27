/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef COMMON_DPI_WORKER_H_
#define COMMON_DPI_WORKER_H_

#include <doca_dpi.h>

#include "telemetry.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dpi_worker_action {
	DPI_WORKER_ALLOW,
	DPI_WORKER_DROP,
	DPI_WORKER_RSS_FLOW
};

struct dpi_worker_attr {
	/* Will be called on (first) match */
	enum dpi_worker_action (*dpi_on_match)(int queue, const struct doca_dpi_result *result,
					       uint32_t fid, void *user_data);
	void (*send_netflow_record)(const struct doca_telemetry_netflow_record *record);

	void *user_data;
	uint64_t max_dpi_depth;		/* Max DPI depth search limit, use 0 for unlimited depth. */
	struct doca_dpi_ctx *dpi_ctx;
};

void printf_signature(struct doca_dpi_ctx *dpi_ctx, uint32_t sig_id, uint32_t fid, bool blocked);

void dpi_worker_lcores_run(int available_cores, int client_id, struct dpi_worker_attr attr);

void dpi_worker_lcores_stop(struct doca_dpi_ctx *dpi_ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* COMMON_DPI_WORKER_H_ */
