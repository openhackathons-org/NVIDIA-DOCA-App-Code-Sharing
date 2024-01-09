#include <bsd/string.h>

#include <cassert>	

#include <doca_mmap.h>
#include <doca_log.h>

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "c/common.h"
#include "c/comm_channel_endpoint.h"

#include "DOCA_dist_fs.h"

#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */

#ifdef __cplusplus
extern "C"
{
#endif

DOCA_LOG_REGISTER(DOCA_DIST_FS);

#define DOCA_CHECK_1( expr ) \
do { \
doca_error_t result = expr ; \
if (result != DOCA_SUCCESS) { \
    return result; \
}} while(0);

#define DOCA_CHECK( expr, state_ptr ) \
do { \
doca_error_t result = expr ; \
if (result != DOCA_SUCCESS) { \
    destroy_host_core_states(state_ptr); \
    return result; \
}} while(0);

void init_host_dma_copy_cfg(void *config) {
    struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;

    strlcpy(cfg->cc_dev_pci_addr, "0b:00.0", DOCA_DEVINFO_PCI_ADDR_SIZE);
    strlcpy(cfg->cc_dev_rep_pci_addr, "0000:03:00.0", DOCA_DEVINFO_REP_PCI_ADDR_SIZE);

}

doca_error_t create_comm_channel_ep(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t **ep) {
    doca_error_t result;

	result = doca_comm_channel_ep_create(ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
		return result;
	}

    return result;
}

doca_error_t create_doca_dev(struct dma_copy_cfg *cfg, struct doca_dev **dev) {
    doca_error_t result;

	result = open_doca_device_with_pci(cfg->cc_dev_pci_addr, &dma_jobs_is_supported, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		return result;
	}

    return result;
}

doca_error_t create_dpu_doca_dev_rep(struct dma_copy_cfg *cfg, struct doca_dev *dev, struct doca_dev_rep **dev_rep) {
    doca_error_t result;

    result = open_doca_device_rep_with_pci(dev, DOCA_DEV_REP_FILTER_NET, cfg->cc_dev_rep_pci_addr, dev_rep);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
        return result;
    }

    return result;
}

static doca_error_t
set_host_comm_channel_properties(struct doca_comm_channel_ep_t *ep, struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_set_device(ep, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device property");
		return result;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, CC_MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
	}

	return result;
}

doca_error_t
init_host_comm_channel_ep(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t **ep, struct doca_dev **dev,
	struct doca_dev_rep **dev_rep)
{
	doca_error_t result;

    result = create_comm_channel_ep(cfg, ep);
    if (result != DOCA_SUCCESS) {
        goto __init_host_exit__;
    }

    result = create_doca_dev(cfg, dev);
    if (result != DOCA_SUCCESS) {
        doca_comm_channel_ep_destroy(*ep);
        goto __init_host_exit__;
    }

	result = set_host_comm_channel_properties(*ep, *dev, *dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set Comm Channel properties");
		doca_comm_channel_ep_destroy(*ep);
		doca_dev_close(*dev);
	}

__init_host_exit__:
	return result;
}

int DOCA_dist_fs_open(const std::string &filename, dist_fs_rpc action, bool dpu_offload) {
    doca_error_t result;
    int exit_status = EXIT_SUCCESS;

    struct dist_fs_core_states state = {0};
    struct dma_copy_cfg dma_copy_cfg = {0};

    const void *export_desc = nullptr;
	size_t export_desc_len;

	struct doca_comm_channel_ep_t *ep = nullptr;
	struct doca_comm_channel_addr_t *peer_addr = nullptr;

	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create LOG: %s", doca_get_error_string(result));
		return result;
	}

    // step-1 TODO (yiakwy) : parse and populate dist_fs_core_states, dma_copy_cfg from conf
    strlcpy(dma_copy_cfg.file_path, filename.c_str(), MAX_ARG_SIZE);

    init_host_dma_copy_cfg(static_cast<void *>(&dma_copy_cfg));

	// TODO (yiakwy) : init host DMA comm channel endpoint device
    init_host_comm_channel_ep(&dma_copy_cfg, &ep, &state.dev, &state.dev_rep);

    // step-2 connect host to DPU
    DOCA_CHECK_1( open_doca_device_with_pci(dma_copy_cfg.cc_dev_pci_addr, &dma_jobs_is_supported, &state.dev) )
    
	DOCA_CHECK_1( host_negotiate_dma_direction_and_size(&dma_copy_cfg, ep, &peer_addr) )

    // step-3 create remote memory mapping block
    DOCA_CHECK( create_host_core_states(&state), &state )
    DOCA_CHECK( doca_mmap_set_permissions(state.src_mmap, DOCA_ACCESS_DPU_READ_ONLY), &state )
    DOCA_CHECK( doca_mmap_set_memrange(state.src_mmap, dma_copy_cfg.message_buf, dma_copy_cfg.message_buf_length), &state )
    DOCA_CHECK( doca_mmap_start(state.src_mmap), &state )
    DOCA_CHECK( doca_mmap_export_dpu(state.src_mmap, state.dev, &export_desc, &export_desc_len), &state )

	while ((result = doca_comm_channel_ep_sendto(ep, export_desc, export_desc_len, DOCA_CC_MSG_FLAG_NONE,
						     peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

    // step-4 send source buffer address and offset (entire buffer) to enable DMA and wait until DPU is done
    result = host_send_addr_and_offset(dma_copy_cfg.message_buf, dma_copy_cfg.file_size, ep, &peer_addr);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = wait_for_successful_status_msg(ep, &peer_addr);
	if (result != DOCA_SUCCESS) {
		return result;
	}

__cleanup_state__:

	exit_status = EXIT_SUCCESS;



    return exit_status;
}

int DOCA_dist_fs_close(int fd, bool dpu_offload) {
	return DOCA_SUCCESS;
}

#ifdef __cplusplus
}
#endif