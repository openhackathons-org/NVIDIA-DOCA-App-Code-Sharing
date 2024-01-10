#include <stdint.h>
#include <string.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_mmap.h>

#include "dma_com.h"
#include "config.h"
#include "utils.h"

/* Function to check if a given device is capable of executing some job */
typedef doca_error_t (*jobs_check)(struct doca_devinfo *);

doca_error_t
dma_jobs_is_supported(struct doca_devinfo *devinfo)
{
	return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}

doca_error_t
open_doca_device_with_pci(const char *pci_addr, jobs_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t is_addr_equal = 0;
	int res;
	size_t i;

	/* Set default return value */
	*retval = NULL;

	res = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to load doca devices list. Doca_error value: %d", res);
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++)
	{
		res = doca_devinfo_get_is_pci_addr_equal(dev_list[i], pci_addr, &is_addr_equal);
		if (res == DOCA_SUCCESS && is_addr_equal)
		{
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS)
			{
				doca_devinfo_list_destroy(dev_list);
				return res;
			}
		}
	}
	warning("Matching device not found");
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_list_destroy(dev_list);
	return res;
}

doca_error_t open_local_device(const char *pcie_addr, struct core_objects *state)
{
	doca_error_t res;
	res = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to open_doca_device %s", doca_get_error_string(res));
		return res;
	}
	return res;
}

doca_error_t create_server_core_objects(struct core_objects *state)
{
	doca_error_t res;

	res = doca_mmap_create(S_DOCA_MMAP_NAME, &state->mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to create mmap: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_buf_inventory_create(DOCA_INVENTORY_NAME, ELEMENT_IN_INVENTORY, DOCA_BUF_EXTENSION_NONE, &state->buf_inv);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to create buffer inventory: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_dma_create(&(state->dma_ctx));
	if (res != DOCA_SUCCESS)
	{
		error("Unable to create DMA engine: %s\n", doca_get_error_string(res));
		return res;
	}

	state->ctx = doca_dma_as_ctx(state->dma_ctx);

	res = doca_workq_create(DEPTH_WORKQ, &(state->workq));
	if (res != DOCA_SUCCESS)
		error("Unable to create work queue: %s\n", doca_get_error_string(res));

	return res;
}

doca_error_t init_server_core_objects(struct core_objects *state, const uint32_t max_chunks)
{
	doca_error_t res;

	// res = doca_mmap_property_set(state->mmap, MMAP_MAX_NUM_CHUNKS, (uint8_t *const)(&max_chunks),
	// 							 sizeof(max_chunks));
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Unable to set memory map nb chunks: %s\n", doca_get_error_string(res));
	// 	return res;
	// }

	// res = doca_mmap_start(state->mmap);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Unable to start memory map: %s\n", doca_get_error_string(res));
	// 	return res;
	// }

	res = doca_mmap_dev_add(state->mmap, state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to add device to mmap: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_buf_inventory_start(state->buf_inv);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to start buffer inventory: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_ctx_dev_add(state->ctx, state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to register device with DMA context: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_ctx_start(state->ctx);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to start DMA context: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_ctx_workq_add(state->ctx, state->workq);
	if (res != DOCA_SUCCESS)
		error("Unable to register work queue with context: %s\n", doca_get_error_string(res));

	return res;
}

doca_error_t init_client_core_objects(struct core_objects *state, const uint32_t max_chunks)
{
	doca_error_t res;

	res = doca_mmap_create(C_DOCA_MMAP_NAME, &state->mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to create mmap: %s\n", doca_get_error_string(res));
		return res;
	}

	// client chunk is 1. Because export only support single chunk

	res = doca_mmap_dev_add(state->mmap, state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to add device to mmap: %s\n", doca_get_error_string(res));
		return res;
	}

	res = doca_mmap_set_permissions(state->mmap, DOCA_ACCESS_DPU_READ_WRITE);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_set_permissions: %s", doca_get_error_string(res));
		return res;
	}

	res = doca_mmap_start(state->mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to start memory map: %s\n", doca_get_error_string(res));
		return res;
	}

	return res;
}

doca_error_t client_create_dma_mmap(struct doca_dev *dev, struct doca_mmap **mmap, int permission)
{
	doca_error_t res;

	res = doca_mmap_create(C_DOCA_MMAP_NAME, mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to create mmap: %s\n", doca_get_error_string(res));
		return res;
	}

	// uint32_t mmap_perims = 0;

	// if (permission & PER_READ)
	// {
	// 	mmap_perims |= DOCA_MMAP_ACCESS_REMOTE_READ;
	// }
	// if (permission & PER_WRITE)
	// {
	// 	mmap_perims |= DOCA_MMAP_ACCESS_REMOTE_WRITE;
	// 	mmap_perims |= DOCA_MMAP_ACCESS_LOCAL_WRITE;
	// // }
	// res = doca_mmap_property_set(*mmap, DOCA_MMAP_ACCESS, (void *)(&mmap_perims), sizeof(mmap_perims));
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Unable to set memory map nb permission: %s\n", doca_get_error_string(res));
	// 	return res;
	// }

	// !!! this only for HOST
	/* Allow exporting the mmap to DPU for read only operations */
	res = doca_mmap_set_permissions(*mmap, DOCA_ACCESS_DPU_READ_WRITE);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_set_permissions: %s", doca_get_error_string(res));
		return res;
	}

	// res = doca_mmap_start(*mmap);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Unable to start memory map: %s\n", doca_get_error_string(res));
	// 	return res;
	// }

	res = doca_mmap_dev_add(*mmap, dev);
	if (res != DOCA_SUCCESS)
		error("Unable to add device to mmap: %s\n", doca_get_error_string(res));

	return res;
}

doca_error_t populate_mmap(struct doca_mmap *mmap, char *buffer, size_t length, size_t pg_sz)
{
	doca_error_t res;
	info("populate_mmap  st(%#lx)-ed(%#lx)\n", (unsigned long)buffer, (unsigned long)buffer + length);
	// TODO !!! solved
	// !!! PATCH error
	// length -= 0x1000;

	/* Populate the memory map with the allocated memory */
	res = doca_mmap_set_memrange(mmap, buffer, length);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_set_memrange: %s", doca_get_error_string(res));
		return res;
	}

	res = doca_mmap_start(mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_start: %s", doca_get_error_string(res));
		return res;
	}

	return res;
}

void cleanup_server_core_objects(struct core_objects *state)
{
	doca_error_t res;

	res = doca_ctx_workq_rm(state->ctx, state->workq);
	if (res != DOCA_SUCCESS)
		error("Failed to remove work queue from ctx: %s\n", doca_get_error_string(res));

	res = doca_ctx_stop(state->ctx);
	if (res != DOCA_SUCCESS)
		error("Unable to stop DMA context: %s\n", doca_get_error_string(res));

	res = doca_ctx_dev_rm(state->ctx, state->dev);
	if (res != DOCA_SUCCESS)
		error("Failed to remove device from DMA ctx: %s\n", doca_get_error_string(res));

	res = doca_mmap_dev_rm(state->mmap, state->dev);
	if (res != DOCA_SUCCESS)
		error("Failed to remove device from mmap: %s\n", doca_get_error_string(res));
}

void destroy_server_core_objects(struct core_objects *state)
{
	doca_error_t res;

	res = doca_workq_destroy(state->workq);
	if (res != DOCA_SUCCESS)
		error("Failed to destroy work queue: %s\n", doca_get_error_string(res));
	state->workq = NULL;

	res = doca_dma_destroy(state->dma_ctx);
	if (res != DOCA_SUCCESS)
		error("Failed to destroy dma: %s\n", doca_get_error_string(res));
	state->dma_ctx = NULL;
	state->ctx = NULL;

	res = doca_buf_inventory_destroy(state->buf_inv);
	if (res != DOCA_SUCCESS)
		error("Failed to destroy buf inventory: %s\n", doca_get_error_string(res));
	state->buf_inv = NULL;

	res = doca_mmap_destroy(state->mmap);
	if (res != DOCA_SUCCESS)
		error("Failed to destroy mmap: %s\n", doca_get_error_string(res));
	state->mmap = NULL;

	res = doca_dev_close(state->dev);
	if (res != DOCA_SUCCESS)
		error("Failed to close device: %s\n", doca_get_error_string(res));
	state->dev = NULL;
}

void destroy_client_core_objects(struct core_objects *state)
{
	doca_error_t res;
	if (state->mmap != NULL)
	{
		res = doca_mmap_destroy(state->mmap);
		if (res != DOCA_SUCCESS)
			error("Failed to destroy mmap: %s\n", doca_get_error_string(res));
		state->mmap = NULL;
	}
	if (state->dev != NULL)
	{
		res = doca_dev_close(state->dev);
		if (res != DOCA_SUCCESS)
			error("Failed to close device: %s\n", doca_get_error_string(res));
		state->dev = NULL;
	}
	return;
}
