#pragma once

#include <stdbool.h>

#include <doca_error.h>
#include <doca_dev.h>

#ifdef __cplusplus
extern "C"
{
#endif

// meson uses old C compiler standard, which does not support C++11 standard
#define nullptr 0

/* Function to check if a given device is capable of executing some job */
typedef doca_error_t (*jobs_check)(struct doca_devinfo *);

/**
 * Check if given device is capable of excuting a DOCA_DMA_JOB_MEMCPY.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports DOCA_DMA_JOB_MEMCPY and DOCA_ERROR otherwise.
 */
doca_error_t dma_jobs_is_supported(struct doca_devinfo *devinfo);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @pci_addr [in]: PCI address
 * @func [in]: pointer to a function that checks if the device have some job capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_pci(const char *pci_addr, jobs_check func,
					       struct doca_dev **retval);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @local [in]: queries representors of the given local doca device
 * @filter [in]: bitflags filter to narrow the representors in the search
 * @pci_addr [in]: PCI address
 * @retval [out]: pointer to doca_dev_rep struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_rep_with_pci(struct doca_dev *local, enum doca_dev_rep_filter filter,
						   const char *pci_addr, struct doca_dev_rep **retval);

/*
 * Open a DOCA device with a custom set of capabilities
 *
 * @func [in]: pointer to a function that checks if the device have some job capabilities
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_capabilities(jobs_check func, struct doca_dev **retval);

/*
 * Open DOCA device for DMA operation
 *
 * @dev [in]: DOCA DMA capable device to open
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_dma_device(struct doca_dev **dev);

enum dma_copy_mode {
	DMA_COPY_MODE_HOST, /* Run endpoint in Host */
	DMA_COPY_MODE_DPU,  /* Run endpoint in DPU */
	N                   /* Num of attributes */
};

#define MAX_USER_ARG_SIZE 256                 /* Maximum size of user input argument */
#define MAX_ARG_SIZE (MAX_USER_ARG_SIZE + 1)  /* Maximum size of input argument */
#define MAX_USER_TXT_SIZE 4096			      /* Maximum size of user input text */
#define MAX_TXT_SIZE (MAX_USER_TXT_SIZE + 1)  /* Maximum size of input text */
#define MAX_DMA_BUF_SIZE (1024 * 1024)        /* DMA buffer maximum size */
#define PAGE_SIZE sysconf(_SC_PAGESIZE)       /* Page size */
#define WORKQ_DEPTH 32		

struct dma_copy_cfg {
	enum dma_copy_mode mode;                                  /* Node running mode {host, dpu} */
	char file_path[MAX_ARG_SIZE];                             /* File path to copy from (host) or path the save DMA result (dpu) */
	char cc_dev_pci_addr[DOCA_DEVINFO_PCI_ADDR_SIZE];	      /* Comm Channel DOCA device PCI address */
	char cc_dev_rep_pci_addr[DOCA_DEVINFO_REP_PCI_ADDR_SIZE]; /* Comm Channel DOCA device representor PCI address */
	bool is_file_found_locally;                               /* Indicate DMA copy direction */
	char export_desc_path[MAX_ARG_SIZE];                      /* Path to save/read the exported descriptor file */
	char message_buf[MAX_TXT_SIZE];	                          /* Message buffer to copy from the host to dpu and vice veras */
	size_t message_buf_length;                                /* Message buffer length */
	uint32_t file_size;                                       /* File size in bytes */
};

/* core states used DOCA_dist_fs */
struct dist_fs_core_states {
	struct doca_dev *dev;               /* opaque doca device */
	struct doca_dev_rep *dev_rep;    /* opaque doca device rep */    
	struct doca_mmap *src_mmap;         /* opaque doca mmap for source buffer */
	struct doca_mmap *dst_mmap;         /* opaque doca mmap for destination buffer */
	struct doca_buf_inventory *buf_inv; /* opaque doca buffer inventory */
	struct doca_ctx *ctx;               /* opaque doca context */
	struct doca_workq *workq;           /* opaque doca work queue */
};

/*
 * Initiates all DOCA core structures needed by the Host.
 *
 * @state [in]: Structure containing all DOCA core structures
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_host_core_states(struct dist_fs_core_states *state);

/*
 * Destroys all DOCA core structures needed by the Host
 *
 * @state [in]: Structure containing all DOCA core structures
 */
void destroy_host_core_states(struct dist_fs_core_states *state);

/*
 * 64-bit extensions to regular host-to-network/network-to-host functions
 *
 * @value [in]: value to convert
 * @return: host byte order/network byte order
 */
uint64_t ntohq(uint64_t value);
#define htonq ntohq

#ifdef __cplusplus
}
#endif
