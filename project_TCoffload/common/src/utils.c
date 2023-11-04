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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdnoreturn.h>

#include <doca_version.h>

#include "utils.h"

#define MAX_LOCAL_PROPERTY_LEN 256
#define MAX_REMOTE_PROPERTY_LEN 128

DOCA_LOG_REGISTER(UTILS);

noreturn doca_error_t
sdk_version_callback(void *doca_config, void *param)
{
	printf("DOCA SDK     Version (Compilation): %s\n", doca_version());
	printf("DOCA Runtime Version (Runtime):     %s\n", doca_version_runtime());
	/* We assume that when printing DOCA's versions there is no need to continue the program's execution */
	exit(0);
}

doca_error_t
open_doca_device_with_property(enum doca_devinfo_property property, const uint8_t *value, size_t val_size,
			       struct doca_dev **retval, caps_check func)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t val_copy[MAX_LOCAL_PROPERTY_LEN] = {};
	uint8_t buf[MAX_LOCAL_PROPERTY_LEN] = {};
	int res;
	size_t i;
	uint32_t caps;

	/* Set default return value */
	*retval = NULL;

	/* Setup */
	if (val_size > MAX_LOCAL_PROPERTY_LEN) {
		DOCA_LOG_ERR("Value size too large. Failed to locate device.");
		return DOCA_ERROR_INVALID_VALUE;
	}

	res = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", res);
		return res;
	}

	/* Prepare value - lengths are in bytes */
	memcpy(val_copy, value, val_size);
	switch (property) {
	case DOCA_DEVINFO_PROPERTY_IFACE_NAME:
		val_size = 256;
		break;
	case DOCA_DEVINFO_PROPERTY_IBDEV_NAME:
		val_size = 64;
		break;
	case DOCA_DEVINFO_PROPERTY_VUID:
		val_size = 128;
		break;
	case DOCA_DEVINFO_PROPERTY_PCI_ADDR:
		val_size = sizeof(struct doca_pci_bdf);
		break;
	case DOCA_DEVINFO_PROPERTY_IPV4_ADDR:
		val_size = 4;
		break;
	case DOCA_DEVINFO_PROPERTY_IPV6_ADDR:
		val_size = 16;
		break;
	default:
		res = DOCA_ERROR_INVALID_VALUE;
		goto Finish;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		res = doca_devinfo_property_get(dev_list[i], property, buf, val_size);
		if (res == DOCA_SUCCESS && memcmp(buf, val_copy, val_size) == 0) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i], &caps) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS)
				goto Finish;
		}
	}

	DOCA_LOG_ERR("Matching device not found.");
	res = DOCA_ERROR_NOT_FOUND;

Finish:
	doca_devinfo_list_destroy(dev_list);
	return res;
}

doca_error_t
open_remote_doca_device_with_property(struct doca_dev *local, enum doca_dev_remote_filter filter,
				      enum doca_devinfo_remote_property property, const uint8_t *value,
				      size_t val_size, struct doca_dev_remote **retval)
{
	uint32_t nb_rdevs = 0;
	struct doca_devinfo_remote **remote_dev_list = NULL;
	uint8_t val_copy[MAX_REMOTE_PROPERTY_LEN] = {};
	uint8_t buf[MAX_REMOTE_PROPERTY_LEN] = {};
	int res;
	size_t i;

	*retval = NULL;
	if (val_size > MAX_REMOTE_PROPERTY_LEN) {
		DOCA_LOG_ERR("Value size too large. Ignored.");
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Prepare value */
	memcpy(val_copy, value, val_size);
	switch (property) {
	case DOCA_DEVINFO_REMOTE_PROPERTY_VUID:
		val_size = 128;
		break;
	default:
		res = DOCA_ERROR_INVALID_VALUE;
		goto Finish;
	}

	/* Search */
	res = doca_devinfo_remote_list_create(local, filter, &remote_dev_list, &nb_rdevs);
	if (res) {
		DOCA_LOG_ERR("Failed to create devinfo remote list. Remote devices are available only on DPU, do not run on Host.");
		return DOCA_ERROR_INVALID_VALUE;
	}

	for (i = 0; i < nb_rdevs; i++) {
		res = doca_devinfo_remote_property_get(remote_dev_list[i], property, buf, sizeof(buf));
		if (res == DOCA_SUCCESS && memcmp(buf, val_copy, val_size) == 0 &&
		     doca_dev_remote_open(remote_dev_list[i], retval) == DOCA_SUCCESS) {
			res = DOCA_SUCCESS;
			goto Finish;
		}
	}

	DOCA_LOG_ERR("Matching device not found.");
	res = DOCA_ERROR_NOT_FOUND;

Finish:
	doca_devinfo_remote_list_destroy(remote_dev_list);
	return res;
}

doca_error_t
parse_pci_addr(char const *pci_addr, struct doca_pci_bdf *out_bdf)
{
	unsigned int bus_bitmask = 0xFFFFFF00;
	unsigned int dev_bitmask = 0xFFFFFFE0;
	unsigned int func_bitmask = 0xFFFFFFF8;
	uint32_t tmpu;
	char tmps[4];

	if (pci_addr == NULL || strlen(pci_addr) != 7 || pci_addr[2] != ':' || pci_addr[5] != '.')
		return DOCA_ERROR_INVALID_VALUE;

	tmps[0] = pci_addr[0];
	tmps[1] = pci_addr[1];
	tmps[2] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & bus_bitmask) != 0)
		return DOCA_ERROR_INVALID_VALUE;
	out_bdf->bus = tmpu;

	tmps[0] = pci_addr[3];
	tmps[1] = pci_addr[4];
	tmps[2] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & dev_bitmask) != 0)
		return DOCA_ERROR_INVALID_VALUE;
	out_bdf->device = tmpu;

	tmps[0] = pci_addr[6];
	tmps[1] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & func_bitmask) != 0)
		return DOCA_ERROR_INVALID_VALUE;
	out_bdf->function = tmpu;

	return DOCA_SUCCESS;
}

doca_error_t
read_file(char const *path, char **out_bytes, size_t *out_bytes_len)
{
	FILE *file;
	char *bytes;

	file = fopen(path, "rb");
	if (file == NULL)
		return DOCA_ERROR_NOT_FOUND;

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return DOCA_ERROR_IO_FAILED;
	}

	long const nb_file_bytes = ftell(file);

	if (nb_file_bytes == -1) {
		fclose(file);
		return DOCA_ERROR_IO_FAILED;
	}

	if (nb_file_bytes == 0) {
		fclose(file);
		return DOCA_ERROR_INVALID_VALUE;
	}

	bytes = malloc(nb_file_bytes);
	if (bytes == NULL) {
		fclose(file);
		return DOCA_ERROR_NO_MEMORY;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		free(bytes);
		fclose(file);
		return DOCA_ERROR_IO_FAILED;
	}

	size_t const read_byte_count = fread(bytes, 1, nb_file_bytes, file);

	fclose(file);

	if (read_byte_count != nb_file_bytes) {
		free(bytes);
		return DOCA_ERROR_IO_FAILED;
	}

	*out_bytes = bytes;
	*out_bytes_len = read_byte_count;

	return DOCA_SUCCESS;
}
