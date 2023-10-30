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

#include <time.h>
#include <bsd/string.h>

#include <rte_compat.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_sft.h>

#include "sig_db.h"
#include "utils.h"

DOCA_LOG_REGISTER(SIGDB);

#define MAX_SIG_APP_NAME 64

static struct rte_hash *sig_db_handle;

struct sig_info {
	uint32_t sig_id;
	char app_name[MAX_SIG_APP_NAME];
	struct tm timestamp;
	uint32_t num_fids;
	bool block;
};

void
sig_db_init(void)
{
	static struct rte_hash_parameters signature_hash_db = {
		.name = "signature_hash_db",
		.entries = 2048,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		/* Needed when using multithreading */
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
	};

	sig_db_handle = rte_hash_create(&signature_hash_db);
	if (sig_db_handle == NULL)
		APP_EXIT("Creating signature database failed");
}

void
sig_db_destroy(void)
{
	uint32_t flow = 0;
	int *key;
	struct sig_info *data;

	while (rte_hash_iterate(sig_db_handle, (const void **)&key,
		(void **)&data, &flow) != -ENOENT) {
		if (data != NULL)
			rte_free(data);
	}
	rte_hash_free(sig_db_handle);
}

bool
sig_db_sig_info_get_block_status(uint32_t sig_id)
{
	struct sig_info *sig_info = NULL;

	sig_info = sig_db_sig_info_get(sig_id);
	if (sig_info == NULL)
		return false;
	return sig_info->block;
}

void
sig_db_sig_info_set_block_status(uint32_t sig_id, bool block)
{
	struct sig_info *sig_info = NULL;

	sig_info = sig_db_sig_info_get(sig_id);
	if (sig_info == NULL) {
		DOCA_LOG_DBG("Sig_id=%d does not exist!", sig_id);
		sig_db_sig_info_create(sig_id, NULL, block);
		sig_info = sig_db_sig_info_get(sig_id);
		if (sig_info == NULL)
			APP_EXIT("Signature info with sig_id=[%u] not found in signature database", sig_id);
	}
	sig_info->block = block;
}

void
sig_db_sig_info_fids_inc(uint32_t sig_id)
{
	struct sig_info *info = sig_db_sig_info_get(sig_id);

	if (info == NULL)
		APP_EXIT("Signature info with sig_id=[%u] not found in signature database", sig_id);
	info->num_fids++;
}

void
sig_db_sig_info_set(uint32_t sig_id, char *app_name)
{
	struct sig_info *info = sig_db_sig_info_get(sig_id);

	if (info == NULL)
		APP_EXIT("Signature info with sig_id=[%u] not found in signature database", sig_id);
	strlcpy(info->app_name, app_name, MAX_SIG_APP_NAME);
}

struct sig_info *
sig_db_sig_info_get(uint32_t sig_id)
{
	struct sig_info *data;

	if (rte_hash_lookup_data(sig_db_handle, &sig_id, (void **)&data) >= 0)
		return data;
	return NULL;
}

void
sig_db_sig_info_create(uint32_t sig_id, char *app_name, bool block)
{
	struct sig_info *data = (struct sig_info *)rte_zmalloc(NULL, sizeof(struct sig_info), 0);

	assert(data != NULL);
	data->sig_id = sig_id;
	data->block = block;
	if (app_name == NULL)
		strcpy(data->app_name, "NO_MATCH");
	else
		strlcpy(data->app_name, app_name, MAX_SIG_APP_NAME);

	if (rte_hash_add_key_data(sig_db_handle, &sig_id, data) != 0)
		APP_EXIT("Cannot add hash key");
}

int
sig_database_write_to_csv(void *csv_filename)
{
	uint32_t app = 0;
	int *key;
	struct sig_info *data;
	FILE *csv;

	csv = fopen((char *)csv_filename, "w");
	if (csv == NULL) {
		DOCA_LOG_ERR("Failed to open CSV file!");
		return -1;
	}
	fprintf(csv, "SIG_ID,APP_NAME,FIDS,BLOCKED\n");
	while (rte_hash_iterate(sig_db_handle, (const void **)&key,
		(void **)&data, &app) != -ENOENT) {
		fprintf(csv, "%u,%s,%u,%u\n", data->sig_id, data->app_name,
					      data->num_fids, data->block);
	}
	fclose(csv);
	return 0;
}
