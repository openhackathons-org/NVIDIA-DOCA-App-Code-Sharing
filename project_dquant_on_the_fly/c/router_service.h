#pragma once

/*
namespace doca_dist_fs {



} // namespace doca_dist_fs
 */

#ifdef __cplusplus
extern "C"
{
#endif

static bool end_service; /* Shared variable to allow for a proper shutdown */

/*
 * Signals handler function
 * Once a signal is received by the application, update the shared variable between the send/receive threads and quit
 *
 * @signum [in]: signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		end_service = true;
	}
}

/*
 * Start DPU router service
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
int start_router_service(int argc, char **argv);

/*
 * Run DOCA Comm Channel server sample
 *
 * @server_name [in]: Server Name
 * @dev_pci_addr [in]: PCI address for device
 * @rep_pci_addr [in]: PCI address for device representor
 * @text [in]: Server message
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
create_comm_channel_server(const char *server_name, const char *dev_pci_addr, const char *rep_pci_addr, const char *text);

int main(int argc, char **argv) {

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    return start_router_service(argc, argv);
}


#ifdef __cplusplus
}
#endif