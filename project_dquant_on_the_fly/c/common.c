#include <bsd/string.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>

// #include <doca_dev.h>

#include <doca_dma.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "common.h"

#ifdef __cplusplus
extern "C"
{
#endif

DOCA_LOG_REGISTER(COMMON);

/* Get LSB at position N from logical value V */
#define GET_BYTE(V, N)	((uint8_t)((V) >> ((N) * 8) & 0xFF))
/* Set byte value V at the LSB position N */
#define SET_BYTE(V, N)	(((V) & 0xFF)  << ((N) * 8))

doca_error_t
dma_jobs_is_supported(struct doca_devinfo *devinfo)
{
	return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}

// TODO (yiakwy) : refactor with open_doca_device_with_capabilities
doca_error_t
open_doca_device_with_pci(const char *pci_addr, jobs_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t is_addr_equal = 0;
	int res;
	size_t i;

	/* Set default return value */
	*retval = nullptr;

	res = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", res);
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
        char target_pcie_addr[DOCA_DEVINFO_PCI_ADDR_SIZE];

        res = doca_devinfo_get_pci_addr_str(dev_list[i], target_pcie_addr);
        DOCA_LOG_INFO("Retrieve device pcie addr : %s.", target_pcie_addr);
        /*
		res = doca_devinfo_get_is_pci_addr_equal(dev_list[i], pci_addr, &is_addr_equal);
         */
        if (res == DOCA_SUCCESS) {
            if (!strcmp(target_pcie_addr, pci_addr)) {
                is_addr_equal = 1;
            }
        }
		if (res == DOCA_SUCCESS && is_addr_equal) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS) {
				doca_devinfo_list_destroy(dev_list);
				return res;
			}
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_list_destroy(dev_list);
	return res;
}

doca_error_t
open_doca_device_rep_with_pci(struct doca_dev *local, enum doca_dev_rep_filter filter, const char *pci_addr,
			      struct doca_dev_rep **retval)
{
	uint32_t nb_rdevs = 0;
	struct doca_devinfo_rep **rep_dev_list = NULL;
	uint8_t is_addr_equal = 0;
	doca_error_t result;
	size_t i;

	*retval = NULL;

	/* Search */
	result = doca_devinfo_rep_list_create(local, filter, &rep_dev_list, &nb_rdevs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR(
			"Failed to create devinfo representors list. Representor devices are available only on DPU, do not run on Host");
		return DOCA_ERROR_INVALID_VALUE;
	}

	for (i = 0; i < nb_rdevs; i++) {
        char target_pcie_addr[DOCA_DEVINFO_REP_PCI_ADDR_SIZE];

        result = doca_devinfo_rep_get_pci_addr_str(rep_dev_list[i], target_pcie_addr);
        DOCA_LOG_INFO("Retrieve device rep pcie addr : %s.", target_pcie_addr);
		
		/*
		result = doca_devinfo_rep_get_is_pci_addr_equal(rep_dev_list[i], pci_addr, &is_addr_equal);
		 */
		if (result == DOCA_SUCCESS && is_addr_equal &&
		    doca_dev_rep_open(rep_dev_list[i], retval) == DOCA_SUCCESS) {
			doca_devinfo_rep_list_destroy(rep_dev_list);
			return DOCA_SUCCESS;
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	doca_devinfo_rep_list_destroy(rep_dev_list);
	return DOCA_ERROR_NOT_FOUND;
}

doca_error_t
open_doca_device_with_capabilities(jobs_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	doca_error_t result;
	size_t i;

	/* Set default return value */
	*retval = NULL;

	result = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", result);
		return result;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		/* If any special capabilities are needed */
		if (func(dev_list[i]) != DOCA_SUCCESS)
			continue;

		/* If device can be opened */
		if (doca_dev_open(dev_list[i], retval) == DOCA_SUCCESS) {
			doca_devinfo_list_destroy(dev_list);
			return DOCA_SUCCESS;
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	doca_devinfo_list_destroy(dev_list);
	return DOCA_ERROR_NOT_FOUND;
}

// TODO (yiakwy) : refactor with open_doca_device_with_pci
doca_error_t
open_dma_device(struct doca_dev **dev)
{
	doca_error_t result;

	result = open_doca_device_with_capabilities(dma_jobs_is_supported, dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to open DOCA DMA capable device");

	return result;
}

doca_error_t _create_core_states(struct dist_fs_core_states *state) {
	doca_error_t res;

	res = doca_mmap_create(NULL, &state->src_mmap);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create mmap: %s", doca_get_error_string(res));
		return res;
	}

	res = doca_mmap_dev_add(state->src_mmap, state->dev);
	if (res != DOCA_SUCCESS)
		DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(res));

	return res;
}

void _destroy_core_states(struct dist_fs_core_states *state) {
	doca_error_t res;

	res = doca_mmap_destroy(state->src_mmap);
	if (res != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy mmap: %s", doca_get_error_string(res));
	state->src_mmap = NULL;

	res = doca_dev_close(state->dev);
	if (res != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close device: %s", doca_get_error_string(res));

	state->dev = NULL;
}

doca_error_t
create_host_core_states(struct dist_fs_core_states *state)
{
    return _create_core_states(state);
}

void 
destroy_host_core_states(struct dist_fs_core_states *state)
{
    _destroy_core_states(state);
}

uint64_t
ntohq(uint64_t value)
{
	const int numeric_one = 1;

	/* If we are in a Big-Endian architecture, we don't need to do anything */
	if (*(const uint8_t *)&numeric_one != 1)
		return value;

	/* Swap the 8 bytes of our value */
	value = SET_BYTE((uint64_t)GET_BYTE(value, 0), 7) | SET_BYTE((uint64_t)GET_BYTE(value, 1), 6) |
		SET_BYTE((uint64_t)GET_BYTE(value, 2), 5) | SET_BYTE((uint64_t)GET_BYTE(value, 3), 4) |
		SET_BYTE((uint64_t)GET_BYTE(value, 4), 3) | SET_BYTE((uint64_t)GET_BYTE(value, 5), 2) |
		SET_BYTE((uint64_t)GET_BYTE(value, 6), 1) | SET_BYTE((uint64_t)GET_BYTE(value, 7), 0);

	return value;
}

#ifdef __cplusplus
}
#endif