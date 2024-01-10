#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <doca_comm_channel.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_types.h>

#include "config.h"
#include "utils.h"
#include "cc_channel.h"
#include "dma_com.h"
#include "dma_func.h"
static struct doca_comm_channel_ep_t *ep = NULL;
static struct doca_comm_channel_addr_t *peer_addr = NULL;

static doca_error_t open_doca_device_rep_with_pci(struct doca_dev *local, enum doca_dev_rep_filter filter, const char *pci_bdf, struct doca_dev_rep **retval)
{
	uint32_t nb_rdevs = 0;
	struct doca_devinfo_rep **rep_dev_list = NULL;
	uint8_t is_addr_equal = 0;
	doca_error_t result;
	size_t i;

	*retval = NULL;

	/* Search */
	result = doca_devinfo_rep_list_create(local, filter, &rep_dev_list, &nb_rdevs);
	if (result != DOCA_SUCCESS)
	{
		error("Failed to create devinfo representors list. Representor devices are available only on DPU, do not run on Host: %s\n",doca_get_error_string(result));
		return DOCA_ERROR_INVALID_VALUE;
	}
	info("rep_number (%d)\n", nb_rdevs);
	for (i = 0; i < nb_rdevs; i++)
	{ // is_pci_addr_equal(dev_list[i], pci_addr, &is_addr_equal);
		result = doca_devinfo_rep_get_is_pci_addr_equal(rep_dev_list[i], pci_bdf, &is_addr_equal);
		if (result == DOCA_SUCCESS && is_addr_equal &&
			doca_dev_rep_open(rep_dev_list[i], retval) == DOCA_SUCCESS)
		{
			doca_devinfo_rep_list_destroy(rep_dev_list);
			return DOCA_SUCCESS;
		}
	}

	error("Matching device not found");
	doca_devinfo_rep_list_destroy(rep_dev_list);
	return DOCA_ERROR_NOT_FOUND;
}

bool open_comm_channel_client()
{
	doca_error_t res;
	struct core_objects *state = get_core_object();
	/* Create Comm Channel endpoint */
	res = doca_comm_channel_ep_create(&ep);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to create Comm Channel client endpoint: %s\n", doca_get_error_string(res));
		return false;
	}
	/* Set all endpoint properties */
	res = doca_comm_channel_ep_set_device(ep, state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to set device property\n");
		return false;
	}

	res = doca_comm_channel_ep_set_max_msg_size(ep, MAX_MSG_SIZE);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to set max_msg_size property\n");
		return false;
	}

	// res = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Failed to set snd_queue_size property");
	// 	return false;
	// }

	// res = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Failed to set rcv_queue_size property");
	// 	return false;
	// }

	info("Comm Channel client endpoint was created successfully\n");

	/* Connect to server node */
	res = doca_comm_channel_ep_connect(ep, COMM_CHANN_NAME, &peer_addr);
	if (res != DOCA_SUCCESS)
	{
		error("Couldn't establish a connection with the server: %s\n", doca_get_error_string(res));
		return false;
	}

	/* Make sure peer address is valid */
	while ((res = doca_comm_channel_peer_addr_update_info(peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS)
	{
		usleep(1);
	}
	if (res != DOCA_SUCCESS)
	{
		error("Failed to validate the connection with the DPU: %s\n", doca_get_error_string(res));
		return false;
	}

	info("Connection to server was established successfully\n");
	return true;
}

// ! must finish the open of local device before call this function
bool open_comm_channel_server()
{
	struct core_objects *state = get_core_object();
	doca_error_t res;
	char rep_pci_addr[PCI_BUF_SIZE] = REP_PCI_BUS_ADDR;
	res = doca_comm_channel_ep_create(&ep);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to create Comm Channel endpoint: %s\n", doca_get_error_string(res));
		return false;
	}

	res = open_doca_device_rep_with_pci(state->dev, DOCA_DEV_REP_FILTER_NET, rep_pci_addr, &(state->cc_dev_rep));
	if (res != DOCA_SUCCESS)
	{
		error("Failed to open Comm Channel DOCA device representor based on PCI address\n");
		return false;
	}

	res = doca_comm_channel_ep_set_device(ep, state->dev);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to set device property\n");
		return false;
	}
	res = doca_comm_channel_ep_set_max_msg_size(ep, MAX_MSG_SIZE);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to set max_msg_size property\n");
		return false;
	}

	// res = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Failed to set snd_queue_size property");
	// 	return false;
	// }

	// res = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	// if (res != DOCA_SUCCESS)
	// {
	// 	error("Failed to set rcv_queue_size property");
	// 	return false;
	// }

	res = doca_comm_channel_ep_set_device_rep(ep, state->cc_dev_rep);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to set DOCA device representor property\n");
		return false;
	}

	/* Start listen for new connections */
	res = doca_comm_channel_ep_listen(ep, COMM_CHANN_NAME);
	if (res != DOCA_SUCCESS)
	{
		error("Comm Channel server couldn't start listening: %s\n", doca_get_error_string(res));
		return false;
	}

	info("Comm Channel Server started Listening, waiting for new connection\n");
	return true;
}

// server and client are same
bool close_comm_channel()
{
	doca_error_t res;
	struct core_objects *state = get_core_object();
	/* Disconnect from current connection */
	res = doca_comm_channel_ep_disconnect(ep, peer_addr);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to disconnect channel: %s\n", doca_get_error_string(res));
	}

	res = doca_comm_channel_ep_destroy(ep);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to destroy Comm Channel endpoint: %s\n", doca_get_error_string(res));
		return false;
	}
	if (state != NULL && state->cc_dev_rep != NULL)
	{
		res = doca_dev_rep_close(state->cc_dev_rep);
		if (res != DOCA_SUCCESS)
		{
			error("Failed to close cc rep device\n");
			return false;
		}
	}
	return true;
}

size_t read_comm_channel(void *buf, size_t max_len)
{
	doca_error_t res;
	/* Wait until a message is received */
	// !!!  note: Wether to set max_len when DOCA_ERROR_AGAIN every time
	while ((res = doca_comm_channel_ep_recvfrom(ep, buf, &max_len, DOCA_CC_MSG_FLAG_NONE, &peer_addr)) == DOCA_ERROR_AGAIN)
	{
		usleep(1);
	};
	if (res != DOCA_SUCCESS)
	{
		error("Message was not received: %s", doca_get_error_string(res));
		return -1;
	}
	return max_len;
}

size_t write_comm_channel(void *buf, size_t len)
{
	doca_error_t res;
	while ((res = doca_comm_channel_ep_sendto(ep, buf, len, DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN)
	{
		usleep(1);
	};
	if (res != DOCA_SUCCESS)
	{
		info("Response was not sent successfully: %s", doca_get_error_string(res));
		return 0;
	}
	return len;
}
