/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bsd/string.h>
#include <ctype.h>
#include <sys/queue.h>
#include <unistd.h>
#include <linux/types.h>

#include <rte_string_fns.h>

#include <doca_log.h>

#include "telemetry.h"

DOCA_LOG_REGISTER(NETFLOW_TELEMETRY);

struct rte_ring *netflow_pending_ring, *netflow_freelist_ring;

static struct doca_telemetry_netflow_record data_to_send[NETFLOW_QUEUE_SIZE];
static struct doca_telemetry_netflow_record *data_to_send_ptr[NETFLOW_QUEUE_SIZE];

struct doca_telemetry_netflow_template *netflow_template;

static doca_error_t add_netflow_field(uint16_t type, uint16_t length)
{
	struct doca_telemetry_netflow_flowset_field *field;
	doca_error_t ret;

	ret = doca_telemetry_netflow_field_create(&field);
	if (ret != DOCA_SUCCESS)
		return ret;
	doca_telemetry_netflow_field_set_type(field, type);
	doca_telemetry_netflow_field_set_length(field, length);

	ret = doca_telemetry_netflow_template_add_field(netflow_template, field);
	if (ret != DOCA_SUCCESS)
		doca_telemetry_netflow_field_destroy(field);
	return ret;
}

static doca_error_t
init_template_fields(void)
{
	doca_error_t ret = DOCA_SUCCESS;

	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV4_SRC_ADDR,
					DOCA_TELEMETRY_NETFLOW_IPV4_SRC_ADDR_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV4_DST_ADDR,
					DOCA_TELEMETRY_NETFLOW_IPV4_DST_ADDR_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV6_SRC_ADDR,
					DOCA_TELEMETRY_NETFLOW_IPV6_SRC_ADDR_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV6_DST_ADDR,
					DOCA_TELEMETRY_NETFLOW_IPV6_DST_ADDR_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV4_NEXT_HOP,
					DOCA_TELEMETRY_NETFLOW_IPV4_NEXT_HOP_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IPV6_NEXT_HOP,
					DOCA_TELEMETRY_NETFLOW_IPV6_NEXT_HOP_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_INPUT_SNMP, DOCA_TELEMETRY_NETFLOW_INPUT_SNMP_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_OUTPUT_SNMP, DOCA_TELEMETRY_NETFLOW_OUTPUT_SNMP_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_L4_SRC_PORT, DOCA_TELEMETRY_NETFLOW_L4_SRC_PORT_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_L4_DST_PORT, DOCA_TELEMETRY_NETFLOW_L4_DST_PORT_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_TCP_FLAGS, DOCA_TELEMETRY_NETFLOW_TCP_FLAGS_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_PROTOCOL, DOCA_TELEMETRY_NETFLOW_PROTOCOL_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_SRC_TOS, DOCA_TELEMETRY_NETFLOW_SRC_TOS_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_SRC_AS, DOCA_TELEMETRY_NETFLOW_SRC_AS_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_DST_AS, DOCA_TELEMETRY_NETFLOW_DST_AS_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_SRC_MASK, DOCA_TELEMETRY_NETFLOW_SRC_MASK_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_DST_MASK, DOCA_TELEMETRY_NETFLOW_DST_MASK_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IN_PKTS, DOCA_TELEMETRY_NETFLOW_IN_PKTS_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_IN_BYTES, DOCA_TELEMETRY_NETFLOW_IN_BYTES_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_FIRST_SWITCHED,
					DOCA_TELEMETRY_NETFLOW_FIRST_SWITCHED_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_LAST_SWITCHED,
					DOCA_TELEMETRY_NETFLOW_LAST_SWITCHED_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_CONNECTION_TRANSACTION_ID,
					DOCA_TELEMETRY_NETFLOW_CONNECTION_TRANSACTION_ID_DEFAULT_LENGTH);
	ret |= add_netflow_field(DOCA_TELEMETRY_NETFLOW_APPLICATION_NAME,
					DOCA_TELEMETRY_NETFLOW_APPLICATION_NAME_DEFAULT_LENGTH);
	if (ret != DOCA_SUCCESS)
		return DOCA_ERROR_NO_MEMORY;

	return DOCA_SUCCESS;
}

static doca_error_t
get_hostname_ip(char *host_name)
{
	doca_error_t ret = DOCA_SUCCESS;
	char host[256];
	struct hostent *host_entry = NULL;

	 /* Find the host name */
	if (gethostname(host, sizeof(host)) < 0)  {
		switch (errno) {
		case EPERM:
			ret = DOCA_ERROR_NOT_PERMITTED;
			break;
		default:
			ret = DOCA_ERROR_INVALID_VALUE;
			break;
		}
		DOCA_LOG_ERR("Gethostname failed");
		return ret;
	}
	/* Find host information */
	host_entry = gethostbyname(host);
	if (host_entry == NULL)
		strlcpy(host_name, host, 64);
	else
		strlcpy(host_name, host_entry->h_name, 64);

	DOCA_LOG_DBG("Host name: %s", host_name);
	return ret;
}

int
send_netflow_record(void)
{
	doca_error_t ret;
	size_t records_to_send = 0;
	size_t records_sent = 0;
	size_t records_successfully_sent;
	int ring_count = rte_ring_count(netflow_pending_ring);
	static struct doca_telemetry_netflow_record *records[NETFLOW_QUEUE_SIZE];
	/*
	 * Sending the record array
	 * The while loop ensure that all records have been sent, in case just some are sent.
	 * This section should happen periodically with updated the flows.
	 */
	if (ring_count == 0)
		return 0;
	/* We need to dequeue only the records that were enqueued with the allocated memory. */
	records_to_send = rte_ring_dequeue_bulk(netflow_pending_ring, (void **)records, ring_count, NULL);
	while (records_sent < records_to_send) {
		ret = doca_telemetry_netflow_send(netflow_template, (const void **)(records + records_sent),
				records_to_send - records_sent, &records_successfully_sent);
		if (ret != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to send Netflow, error=%d", ret);
			return ret;
		}
		records_sent += records_successfully_sent;
	}
	/* Flushing the buffer sends it to the collector */
	flush_telemetry_netflow_source();
	DOCA_LOG_DBG("Successfully sent %lu netflow records with default template.", records_sent);
	if ((int)rte_ring_enqueue_bulk(netflow_freelist_ring, (void **)records, records_sent, NULL) != records_sent) {
		DOCA_LOG_ERR("Placeholder queue mismatch");
		return -1;
	}
	return 0;
}

void
enqueue_netflow_record_to_ring(const struct doca_telemetry_netflow_record *record)
{
	struct doca_telemetry_netflow_record *tmp_record;
	/* To avoid memory corruption when flows are destroyed, we copy the pointers to a
	 *	preallocated pointer inside freelist ring and enqueue it so the main thread
	 *	can send them.
	 */
	if (rte_ring_mc_dequeue(netflow_freelist_ring, (void **)&tmp_record) != 0) {
		DOCA_LOG_DBG("Placeholder queue is empty");
		return;
	}
	*tmp_record = *record;
	if (rte_ring_mp_enqueue(netflow_pending_ring, tmp_record) != 0) {
		DOCA_LOG_DBG("Netflow queue is full");
		return;
	}
}


void
flush_telemetry_netflow_source(void)
{
	doca_telemetry_netflow_flush();
}

void
destroy_netflow_schema_and_source(void)
{
	rte_ring_free(netflow_pending_ring);
	rte_ring_free(netflow_freelist_ring);

	doca_telemetry_netflow_destroy();

}

doca_error_t
init_netflow_schema_and_source(uint8_t id, char *source_tag)
{
	doca_error_t ret;
	int i;
	char hostname[64];
	char *bluefield_rshim = "192.168.100.1";

	ret = doca_telemetry_netflow_template_create(&netflow_template);
	if (ret != DOCA_SUCCESS)
		return ret;

	ret = init_template_fields();
	if (ret != DOCA_SUCCESS)
		return ret;

	ret = doca_telemetry_netflow_init(id);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Cannot init DOCA netflow");
		return ret;
	}

	doca_telemetry_netflow_set_ipc_enabled();

	/* Setting the send_attr struct is recommended for debugging only - use DTS otherwise */
	doca_telemetry_netflow_set_collector_addr(bluefield_rshim);
	doca_telemetry_netflow_set_collector_port(NETFLOW_COLLECTOR_PORT);

	ret = get_hostname_ip(hostname);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Getting hostname failed");
		doca_telemetry_netflow_destroy();
		return ret;
	}

	doca_telemetry_netflow_source_set_id(hostname);
	doca_telemetry_netflow_source_set_tag(source_tag);

	ret = doca_telemetry_netflow_start();
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Cannot start DOCA netflow");
		doca_telemetry_netflow_destroy();
		return ret;
	}
	/* In the Netflow ring scenario, a producer-consumer solution is given where the dpi_worker threads produce
	 * records and enqueues them to a rings struct. The records are consumed by the main thread that dequeues
	 * the records and sends them. This allows avoiding collisions between thread and memory corruption issues.
	 */
	netflow_pending_ring = rte_ring_create("netflow_queue", NETFLOW_QUEUE_SIZE, SOCKET_ID_ANY, RING_F_SC_DEQ);
	netflow_freelist_ring =	rte_ring_create("placeholder_netflow_queue", NETFLOW_QUEUE_SIZE, SOCKET_ID_ANY,
													RING_F_SP_ENQ);
	if (netflow_pending_ring == NULL || netflow_freelist_ring == NULL) {
		doca_telemetry_netflow_destroy();
		return DOCA_ERROR_NO_MEMORY;
	}
	for (i = 0; i < NETFLOW_QUEUE_SIZE; i++)
		data_to_send_ptr[i] = &data_to_send[i];
	if (rte_ring_enqueue_bulk(netflow_freelist_ring, (void **)data_to_send_ptr, NETFLOW_QUEUE_SIZE - 1, NULL) !=
					NETFLOW_QUEUE_SIZE - 1) {
		doca_telemetry_netflow_destroy();
		return DOCA_ERROR_NO_MEMORY;
	}

	return DOCA_SUCCESS;
}
