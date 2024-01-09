#pragma once

#include <doca_comm_channel.h>

#include "common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CC_MAX_MSG_SIZE 4080 /* Comm Channel message maximum size */
#define CC_MAX_QUEUE_SIZE 10 /* Max number of messages on Comm Channel queue */

struct cc_msg_dma_direction {
	bool file_in_host;  /* Indicate where the source file is located */
	uint32_t file_size; /* File size in bytes */
};

struct cc_msg_dma_status {
	bool is_success;    /* Indicate success or failure for last message sent */
};

/*
 * Host side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
host_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr);

/*
 * Host side function to send buffer address and offset
 *
 * @src_buffer [in]: Buffer to send info on
 * @src_buffer_size [in]: Buffer size
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
host_send_addr_and_offset(const char *src_buffer, size_t src_buffer_size, struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr);

/*
 * Wait for status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr);

#ifdef __cplusplus
}
#endif
