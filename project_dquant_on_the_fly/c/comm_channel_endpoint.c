#include <bsd/string.h>

#include <errno.h>

#include <stdint.h>
#include <string.h>

#include <sys/epoll.h>

#include <time.h>
#include <netinet/in.h>

#include <unistd.h>

#include <doca_log.h>

#include "comm_channel_endpoint.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds */

DOCA_LOG_REGISTER(COMM_CHANNEL_EP);

doca_error_t
host_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;

	result = doca_comm_channel_ep_connect(ep, "dpu_dma_deamon", peer_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to establish a connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	while ((result = doca_comm_channel_peer_addr_update_info(*peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to validate the connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Connection to DPU was established successfully");

	/* First byte indicates if file is located on Host, other 4 bytes determine file size */
	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("File was found locally, it will be DMA copied to the DPU");
		host_dma_direction.file_size = htonl(cfg->file_size);
		host_dma_direction.file_in_host = true;
	} else {
		DOCA_LOG_INFO("File was not found locally, it will be DMA copied from the DPU");
		host_dma_direction.file_in_host = false;
	}

	while ((result = doca_comm_channel_ep_sendto(ep, &host_dma_direction, sizeof(host_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Waiting for DPU to send negotiation message");

	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&dpu_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Negotiation message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Negotiation with DPU on file location and size failed");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!cfg->is_file_found_locally)
		cfg->file_size = ntohl(dpu_dma_direction.file_size);

	DOCA_LOG_INFO("Negotiation with DPU on file location and size ended successfully");
	return DOCA_SUCCESS;
}

doca_error_t
host_send_addr_and_offset(const char *src_buffer, size_t src_buffer_size, struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Send the full buffer address and length */
	uint64_t addr_to_send = htonq((uintptr_t)src_buffer);
	uint64_t length_to_send = htonq((uint64_t)src_buffer_size);

	while ((result = doca_comm_channel_ep_sendto(ep, &addr_to_send, sizeof(addr_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send address to start DMA from: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	while ((result = doca_comm_channel_ep_sendto(ep, &length_to_send, sizeof(length_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	DOCA_LOG_INFO(
		"Address and offset to start DMA from sent successfully, waiting for DPU to Ack that DMA finished");

	return result;
}

doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_status msg_status;
	doca_error_t result;
	size_t msg_len, status_msg_len = sizeof(struct cc_msg_dma_status);
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	msg_len = status_msg_len;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&msg_status, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = status_msg_len;
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Status message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (!msg_status.is_success) {
		DOCA_LOG_ERR("Failure status received");
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

#ifdef __cplusplus
}
#endif