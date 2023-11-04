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

#ifndef COMMON_UTILS_H_
#define COMMON_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <doca_error.h>
#include <doca_log.h>
#include <doca_dev.h>

#define APP_EXIT(format, ...)					\
	do {							\
		DOCA_LOG_ERR(format "\n", ##__VA_ARGS__);	\
		exit(1);					\
	} while (0)

typedef doca_error_t (*caps_check)(struct doca_devinfo *, uint32_t *);

doca_error_t sdk_version_callback(void *doca_config, void *param);

/* val_size param should indicate the actual value size and not buffer size. */
doca_error_t open_doca_device_with_property(enum doca_devinfo_property property, const uint8_t *value, size_t val_size,
					    struct doca_dev **retval, caps_check func);

/* val_size param should indicate the actual value size and not buffer size. */
doca_error_t open_remote_doca_device_with_property(struct doca_dev *local, enum doca_dev_remote_filter filter,
						   enum doca_devinfo_remote_property property, const uint8_t *value,
						   size_t val_size, struct doca_dev_remote **retval);

/* parse string pci address into bdf struct */
doca_error_t parse_pci_addr(char const *pci_addr, struct doca_pci_bdf *out_bdf);

/* read the entire content of a file into a buffer */
doca_error_t read_file(char const *path, char **out_bytes, size_t *out_bytes_len);

#endif /* COMMON_UTILS_H_ */
