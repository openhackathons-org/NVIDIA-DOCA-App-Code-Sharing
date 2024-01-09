#include <stdlib.h>

#include <doca_argp.h>
#include <doca_dev.h>

#include <doca_error>
#include <doca_log.h>

#include "common.h"
#include "comm_channel_endpoint.h"
#include "router_service.h"

#ifdef __cplusplus
extern "C"
{
#endif

void init_host_dma_copy_cfg(void *config) {
    struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;

    strlcpy(cfg->cc_dev_pci_addr, "03:00.0", DOCA_DEVINFO_PCI_ADDR_SIZE);
    strlcpy(cfg->cc_dev_rep_pci_addr,  "3b:00.0", DOCA_DEVINFO_REP_PCI_ADDR_SIZE);

}

int start_router_service(int argc, char **argv) {
    doca_error_t result;
    int exit_status = EXIT_SUCCESS;

    struct dma_copy_cfg dma_copy_cfg = {0};

	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create LOG: %s", doca_get_error_string(result));
		return result;
	}

    init_dpu_dma_copy_cfg(static_cast<void *>(&dma_copy_cfg));

    // step-1 TODO (yiakwy) : parse cmdline arguments

    // step-2 : create DPU service to route fs request to the target NVMe storage backend
    result = create_comm_channel_server("dpu_router", cfg.cc_dev_pci_addr, cfg.cc_dev_rep_pci_addr, cfg.message_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("create_comm_channel_server() encountered an error: %s", doca_get_error_string(result));
		goto argp_cleanup;
	}

    exit_status = EXIT_SUCCESS;

argp_cleanup:
	doca_argp_destroy();
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;
}

doca_error_t
create_comm_channel_server(const char *server_name, const char *dev_pci_addr, const char *rep_pci_addr, const char *message_buf)
{
	doca_error_t result;

	char rcv_buf[MAX_MSG_SIZE];
	int response_len = strlen(message_buf) + 1;
	size_t msg_len;

    struct dist_fs_core_states state = {0};

	/* Define Comm Channel endpoint attributes */
	struct doca_comm_channel_ep_t *ep = nullptr;
	struct doca_comm_channel_addr_t *peer_addr = nullptr;

	/* Create Comm Channel endpoint */
	result = doca_comm_channel_ep_create(&ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
		return result;
	}

	/* Open DOCA device according to the given PCI address */
	result = open_doca_device_with_pci(dev_pci_addr, nullptr, &state.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(ep);
		return result;
	}

	/* Open DOCA device representor according to the given PCI address */
	result = open_doca_device_rep_with_pci(state.dev, DOCA_DEV_REP_FILTER_NET, rep_pci_addr, &state.dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
		doca_comm_channel_ep_destroy(ep);
		doca_dev_close(state.dev);
		return result;
	}

	/* Set all endpoint properties */
	result = doca_comm_channel_ep_set_device(ep, state.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set device property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_device_rep(ep, state.dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device representor property");
		goto destroy_cc;
	}

	/* Start listen for new connections */
	result = doca_comm_channel_ep_listen(ep, server_name);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel server couldn't start listening: %s", doca_get_error_string(result));
		goto destroy_cc;
	}

	DOCA_LOG_INFO("Server started Listening, waiting for new connections");

__main_loop__:
	/* Wait until a message is received */
	msg_len = MAX_MSG_SIZE;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)rcv_buf, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       &peer_addr)) == DOCA_ERROR_AGAIN) {

        // TODO (yiakwy) : add peer_addr to a conn set 

		if (end_service) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
		msg_len = MAX_MSG_SIZE;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Message was not received: %s", doca_get_error_string(result));
		goto destroy_cc;
	}

	rcv_buf[MAX_MSG_SIZE - 1] = '\0';
	DOCA_LOG_INFO("Received message: %s", rcv_buf);

    // TODO (yaikwy) : spaw a thread to do the following with conn set

    // TODO (yiakwy) : parse client RPC request

    // TODO (yiakwy) : open the requested file and fill into DMA buffer

    // TODO (yiakwy) : enqueue DMA job to write back to host

	/* Send a response to client */
	while ((result = doca_comm_channel_ep_sendto(ep, message_buf, response_len, DOCA_CC_MSG_FLAG_NONE, peer_addr)) ==
	       DOCA_ERROR_AGAIN) {
		if (end_service) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
	}
	if (result != DOCA_SUCCESS)
		DOCA_LOG_WARN("Response was not sent successfully: %s", doca_get_error_string(result));

    if (!end_service) {
        goto __main_loop__;
    }

destroy_cc:

	/* Disconnect from current connection */
	if (peer_addr != NULL)
		doca_comm_channel_ep_disconnect(ep, peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(ep);

	/* Destroy Comm Channel DOCA device representor */
	doca_dev_rep_close(state.dev_rep);

	/* Destroy Comm Channel DOCA device */
	doca_dev_close(state.dev);

	return result;
}


#ifdef __cplusplus
}
#endif