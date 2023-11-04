/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <bsd/string.h>
#include <inttypes.h>
#include <string.h>

#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_log.h>

#include "flow_parser.h"

DOCA_LOG_REGISTER(FLOW_PARSER);

#define MAX_CMDLINE_INPUT_LEN 512
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define MAX_FIELD_INPUT_LEN 128
#define NAME_STR_LEN 5
#define FWD_STR_LEN 4
#define MISS_FWD_STR_LEN 9
#define MATCH_MASK_STR_LEN 11
#define MONITOR_STR_LEN 8
#define ROOT_ENABLE_STR_LEN 12
#define PORT_ID_STR_LEN 8
#define PIPE_ID_STR_LEN 8
#define ENTRY_ID_STR_LEN 9
#define PIPE_QUEUE_STR_LEN 11
#define PRIORITY_STR_LEN 9
#define FILE_STR_LEN 5
#define TYPE_STR_LEN 5
#define HEXADECIMAL_BASE 16
#define UINT16_CHANGEABLE_FIELD "0xffff"
#define UINT32_CHANGEABLE_FIELD "0xffffffff"
#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32((a << 24) + (b << 16) + (c << 8) + d))

static void (*create_pipe_func)(struct doca_flow_pipe_cfg *, uint16_t, struct doca_flow_fwd *, uint64_t,
				struct doca_flow_fwd *, uint64_t);

static void (*add_entry_func)(uint16_t, uint64_t, struct doca_flow_match *, struct doca_flow_actions *,
			      struct doca_flow_monitor *, struct doca_flow_fwd *, uint64_t, uint32_t);

static void (*add_control_pipe_entry_func)(uint16_t, uint8_t, uint64_t, struct doca_flow_match *,
					   struct doca_flow_match *, struct doca_flow_fwd *, uint64_t);

static void (*destroy_pipe_func)(uint16_t, uint64_t);

static void (*remove_entry_func)(uint16_t, uint64_t);

static void (*port_pipes_flush_func)(uint16_t);

static void (*query_func)(uint64_t, struct doca_flow_query *);

static void (*port_pipes_dump_func)(uint16_t, FILE *);

static struct doca_flow_match pipe_match;
static struct doca_flow_match entry_match;
static struct doca_flow_match match_mask;
static struct doca_flow_actions actions;
static struct doca_flow_monitor monitor;
static struct doca_flow_fwd fwd;
static struct doca_flow_fwd fwd_miss;

static uint16_t pipe_port_id;
static uint64_t fwd_next_pipe_id;
static uint64_t fwd_miss_next_pipe_id;

static uint16_t *rss_queues;

struct cmd_create_pipe_result {
	cmdline_fixed_string_t create;
	cmdline_fixed_string_t pipe;
	cmdline_fixed_string_t params;
};

struct cmd_add_entry_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t params;
};

struct cmd_add_control_pipe_entry_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t control_pipe;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t params;
};

struct cmd_destroy_pipe_result {
	cmdline_fixed_string_t destroy;
	cmdline_fixed_string_t pipe;
	cmdline_fixed_string_t params;
};

struct cmd_rm_entry_result {
	cmdline_fixed_string_t rm;
	cmdline_fixed_string_t entry;
	cmdline_fixed_string_t params;
};

struct cmd_flush_pipes_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t pipes;
	cmdline_fixed_string_t flush;
	cmdline_fixed_string_t port_id;
};

struct cmd_query_result {
	cmdline_fixed_string_t query;
	cmdline_fixed_string_t params;
};

struct cmd_dump_pipe_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t pipes;
	cmdline_fixed_string_t dump;
	cmdline_fixed_string_t params;
};

struct cmd_create_struct_result {
	cmdline_fixed_string_t create;
	cmdline_fixed_string_t flow_struct;
	cmdline_multi_string_t flow_struct_input;
};

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

void
set_action_on_pipe_creation(void (*action)(struct doca_flow_pipe_cfg *cfg, uint16_t port_id, struct doca_flow_fwd *fwd,
					   uint64_t fw_pipe_id, struct doca_flow_fwd *fwd_miss,
					   uint64_t fw_miss_pipe_id))
{
	create_pipe_func = action;
}

void
set_action_on_entry_creation(void (*action)(uint16_t pipe_queue, uint64_t pipe_id, struct doca_flow_match *match,
					    struct doca_flow_actions *actions, struct doca_flow_monitor *monitor,
					    struct doca_flow_fwd *fwd, uint64_t fw_pipe_id, uint32_t flags))
{
	add_entry_func = action;
}

void
set_action_on_control_pipe_entry_creation(void (*action)(uint16_t pipe_queue, uint8_t priority, uint64_t pipe_id,
							 struct doca_flow_match *match,
							 struct doca_flow_match *match_mask, struct doca_flow_fwd *fwd,
							 uint64_t fw_pipe_id))
{
	add_control_pipe_entry_func = action;
}

void
set_action_on_pipe_destruction(void (*action)(uint16_t port_id, uint64_t pipe_id))
{
	destroy_pipe_func = action;
}

void
set_action_on_entry_removal(void (*action)(uint16_t pipe_queue, uint64_t entry_id))
{
	remove_entry_func = action;
}

void
set_action_on_port_pipes_flushing(void (*action)(uint16_t port_id))
{
	port_pipes_flush_func = action;
}

void
set_action_on_query(void (*action)(uint64_t entry_id, struct doca_flow_query *stats))
{
	query_func = action;
}

void
set_action_on_port_pipes_dumping(void (*action)(uint16_t port_id, FILE *fd))
{
	port_pipes_dump_func = action;
}

static void
reset_doca_flow_structs()
{
	memset(&pipe_match, 0, sizeof(pipe_match));
	memset(&entry_match, 0, sizeof(entry_match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&actions, 0, sizeof(actions));
	memset(&monitor, 0, sizeof(monitor));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
}

doca_be32_t
parse_ipv4_str(const char *str_ip)
{
	char *ptr;
	int i;
	int ips[4];

	if (strcmp(str_ip, UINT32_CHANGEABLE_FIELD) == 0)
		return UINT32_MAX;
	for (i = 0; i < 3; i++) {
		ips[i] = atoi(str_ip);
		ptr = strchr(str_ip, '.');
		if (ptr == NULL)
			APP_EXIT("Wrong format of ip string");
		str_ip = ++ptr;
	}
	ips[3] = atoi(ptr);
	return BE_IPV4_ADDR(ips[0], ips[1], ips[2], ips[3]);
}

uint8_t
parse_protocol_string(const char *protocol_str)
{
	if (strcmp(protocol_str, "tcp") == 0)
		return IPPROTO_TCP;
	else if (strcmp(protocol_str, "udp") == 0)
		return IPPROTO_UDP;
	else if (strcmp(protocol_str, "gre") == 0)
		return IPPROTO_GRE;
	DOCA_LOG_ERR("protocol type %s is not supported", protocol_str);
	return 0;
}

static int
parse_port_id_input(const char *port_id_str)
{
	if (strncmp(port_id_str, "port_id=", PORT_ID_STR_LEN) != 0) {
		DOCA_LOG_ERR("Wrong format of port id string: \'port_id=<port_id>\'");
		return -1;
	}
	port_id_str += PORT_ID_STR_LEN;
	return strtol(port_id_str, NULL, 0);
}

static enum doca_flow_tun_type
parse_tun_type_string(const char *tun_type)
{
	if (strcmp(tun_type, "vxlan") == 0)
		return DOCA_FLOW_TUN_VXLAN;
	else if (strcmp(tun_type, "gtpu") == 0)
		return DOCA_FLOW_TUN_GTPU;
	else if (strcmp(tun_type, "gre") == 0)
		return DOCA_FLOW_TUN_GRE;

	DOCA_LOG_ERR("tun type %s is not supported", tun_type);
	return DOCA_FLOW_TUN_NONE;
}

static enum doca_flow_fwd_type
parse_fwd_type(const char *fwd_type)
{
	if (strcmp(fwd_type, "rss") == 0)
		return DOCA_FLOW_FWD_RSS;
	else if (strcmp(fwd_type, "port") == 0)
		return DOCA_FLOW_FWD_PORT;
	else if (strcmp(fwd_type, "pipe") == 0)
		return DOCA_FLOW_FWD_PIPE;
	else if (strcmp(fwd_type, "drop") == 0)
		return DOCA_FLOW_FWD_DROP;

	DOCA_LOG_ERR("fwd type %s is not supported", fwd_type);
	return DOCA_FLOW_FWD_NONE;
}

static enum doca_flow_pipe_type
parse_pipe_type(const char *pipe_type)
{
	if (strcmp(pipe_type, "basic") == 0)
		return DOCA_FLOW_PIPE_BASIC;
	else if (strcmp(pipe_type, "control") == 0)
		return DOCA_FLOW_PIPE_CONTROL;

	DOCA_LOG_ERR("pipe type %s is not supported, default pipe type was taken (basic)", pipe_type);
	return DOCA_FLOW_PIPE_BASIC;
}

static enum doca_flow_ip_type
parse_ip_type(const char *ip_type)
{
	if (strcmp(ip_type, "ipv4") == 0)
		return DOCA_FLOW_IP4_ADDR;
	else if (strcmp(ip_type, "ipv6") == 0)
		return DOCA_FLOW_IP6_ADDR;

	DOCA_LOG_ERR("ip type %s is not supported", ip_type);
	return DOCA_FLOW_ADDR_NONE;
}

static uint8_t
parse_tcp_flag_string(const char *tcp_flag_str)
{
	if (strcmp(tcp_flag_str, "FIN") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_FIN;
	else if (strcmp(tcp_flag_str, "SYN") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_SYN;
	else if (strcmp(tcp_flag_str, "RST") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_RST;
	else if (strcmp(tcp_flag_str, "PSH") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_PSH;
	else if (strcmp(tcp_flag_str, "ACK") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_ACK;
	else if (strcmp(tcp_flag_str, "URG") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_URG;
	else if (strcmp(tcp_flag_str, "ECE") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_ECE;
	else if (strcmp(tcp_flag_str, "CWR") == 0)
		return DOCA_FLOW_MATCH_TCP_FLAG_CWR;
	DOCA_LOG_ERR("tcp flag %s is not supported", tcp_flag_str);
	return 0;
}

static void
parse_mac_address(char *mac_addr_str, uint8_t *mac_addr)
{
	char *ptr;
	int i;

	for (i = 0; i < MAC_ADDR_LEN - 1; i++) {
		mac_addr[i] = strtol(mac_addr_str, NULL, HEXADECIMAL_BASE);
		ptr = strchr(mac_addr_str, ':');
		if (ptr)
			mac_addr_str = ++ptr;
		else {
			DOCA_LOG_ERR("Wrong format of mac address");
			return;
		}
	}
	mac_addr[MAC_ADDR_LEN - 1] = strtol(ptr, NULL, HEXADECIMAL_BASE);
}

static void
parse_ipv6_str(const char *str_ip, doca_be32_t *ipv6_addr)
{
	char *ptr;
	int i;
	int j;

	for (i = 0; i < IP_ADDR_LEN; i++) {
		int ips[2];

		for (j = 0; j < 2; j++) {
			ips[j] = strtol(str_ip, &ptr, HEXADECIMAL_BASE);
			if (ptr)
				str_ip = ++ptr;
			else {
				DOCA_LOG_DBG("Wrong format of ip string");
				return;
			}
		}
		ipv6_addr[i] = RTE_BE32((ips[0] << 16) + ips[1]);
	}
}

static uint16_t *
parse_rss_queues(char *rss_queues_str, int num_of_queues)
{
	int i;

	if (rss_queues)
		free(rss_queues);
	rss_queues = malloc(sizeof(uint16_t) * num_of_queues);
	if (rss_queues == NULL) {
		DOCA_LOG_ERR("failed to allocate rss queues");
		return NULL;
	}

	for (i = 0; i < num_of_queues - 1; i++) {
		rss_queues[i] = strtol(rss_queues_str, NULL, 0);
		rss_queues_str = rss_queues_str + 2;
	}
	rss_queues[num_of_queues - 1] = strtol(rss_queues_str, NULL, 0);
	return rss_queues;
}

static bool
parse_bool_string(char *bool_str)
{
	if (strcmp(bool_str, "true") == 0)
		return true;
	else if (strcmp(bool_str, "false") == 0)
		return false;
	DOCA_LOG_ERR("bool type must be true or false");
	return false;
}

static void
parse_monitor_field(char *field_name, char *value, void *struct_ptr)
{
	struct doca_flow_monitor *monitor = (struct doca_flow_monitor *)struct_ptr;

	if (strcmp(field_name, "flags") == 0)
		monitor->flags = (uint8_t)strtol(value, NULL, 0);

	else if (strcmp(field_name, "cir") == 0)
		monitor->cir = strtol(value, NULL, 0);

	else if (strcmp(field_name, "cbs") == 0)
		monitor->cbs = strtol(value, NULL, 0);

	else if (strcmp(field_name, "aging") == 0)
		monitor->aging = strtol(value, NULL, 0);

	else
		DOCA_LOG_ERR("%s is not supported field in monitor", field_name);
}

static void
parse_fwd_field(char *field_name, char *value, void *struct_ptr)
{
	struct doca_flow_fwd *fwd = (struct doca_flow_fwd *)struct_ptr;

	if (strcmp(field_name, "type") == 0)
		fwd->type = parse_fwd_type(value);

	else if (strcmp(field_name, "rss_flags") == 0)
		fwd->rss_flags = strtol(value, NULL, 0);

	else if (strcmp(field_name, "rss_queues") == 0)
		fwd->rss_queues = parse_rss_queues(value, fwd->num_of_queues);

	else if (strcmp(field_name, "num_of_queues") == 0)
		fwd->num_of_queues = strtol(value, NULL, 0);

	else if (strcmp(field_name, "rss_mark") == 0)
		fwd->rss_mark = strtol(value, NULL, 0);

	else if (strcmp(field_name, "port_id") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			fwd->port_id = UINT16_MAX;
		else
			fwd->port_id = strtol(value, NULL, 0);

	} else if (strcmp(field_name, "next_pipe_id") == 0)
		fwd_next_pipe_id = strtol(value, NULL, 0);

	else
		DOCA_LOG_ERR("%s is not supported field in fwd", field_name);
}

static void
parse_fwd_miss_field(char *field_name, char *value, void *struct_ptr)
{
	struct doca_flow_fwd *fwd_miss = (struct doca_flow_fwd *)struct_ptr;

	if (strcmp(field_name, "type") == 0)
		fwd_miss->type = parse_fwd_type(value);

	else if (strcmp(field_name, "rss_flags") == 0)
		fwd_miss->rss_flags = strtol(value, NULL, 0);

	else if (strcmp(field_name, "rss_queues") == 0)
		fwd_miss->rss_queues = parse_rss_queues(value, fwd_miss->num_of_queues);

	else if (strcmp(field_name, "num_of_queues") == 0)
		fwd_miss->num_of_queues = strtol(value, NULL, 0);

	else if (strcmp(field_name, "rss_mark") == 0)
		fwd_miss->rss_mark = strtol(value, NULL, 0);

	else if (strcmp(field_name, "port_id") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			fwd_miss->port_id = UINT16_MAX;
		else
			fwd_miss->port_id = strtol(value, NULL, 0);

	} else if (strcmp(field_name, "next_pipe_id") == 0)
		fwd_miss_next_pipe_id = strtol(value, NULL, 0);

	else
		DOCA_LOG_ERR("%s is not supported field in fwd_miss", field_name);
}

static void
parse_actions_field(char *field_name, char *value, void *struct_ptr)
{
	struct doca_flow_actions *action = (struct doca_flow_actions *)struct_ptr;

	if (strcmp(field_name, "decap") == 0)
		action->decap = parse_bool_string(value);

	else if (strcmp(field_name, "mod_src_mac") == 0)
		parse_mac_address(value, action->mod_src_mac);

	else if (strcmp(field_name, "mod_dst_mac") == 0)
		parse_mac_address(value, action->mod_dst_mac);

	else if (strcmp(field_name, "mod_src_ip_type") == 0)
		action->mod_src_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "mod_src_ip_addr") == 0) {
		if (action->mod_src_ip.type == DOCA_FLOW_IP4_ADDR)
			action->mod_src_ip.ipv4_addr = parse_ipv4_str(value);
		else if (action->mod_src_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, action->mod_src_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("src ip type is not set, need to set ip type before address");
	} else if (strcmp(field_name, "mod_dst_ip_type") == 0)
		action->mod_dst_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "mod_dst_ip_addr") == 0) {
		if (action->mod_dst_ip.type == DOCA_FLOW_IP4_ADDR)
			action->mod_dst_ip.ipv4_addr = parse_ipv4_str(value);
		else if (action->mod_dst_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, action->mod_dst_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("dst ip type is not set, need to set ip type before address");
	} else if (strcmp(field_name, "mod_src_port") == 0)
		action->mod_src_port = strtol(value, NULL, 0);

	else if (strcmp(field_name, "mod_dst_port") == 0)
		action->mod_dst_port = strtol(value, NULL, 0);

	else if (strcmp(field_name, "ttl") == 0)
		action->ttl = strtol(value, NULL, 0);

	else if (strcmp(field_name, "has_encap") == 0)
		action->has_encap = parse_bool_string(value);

	else if (strcmp(field_name, "encap_src_mac") == 0)
		parse_mac_address(value, action->encap.src_mac);

	else if (strcmp(field_name, "encap_dst_mac") == 0)
		parse_mac_address(value, action->encap.dst_mac);

	else if (strcmp(field_name, "encap_src_ip_type") == 0)
		action->encap.src_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "encap_src_ip_addr") == 0) {
		if (action->encap.src_ip.type == DOCA_FLOW_IP4_ADDR)
			action->encap.src_ip.ipv4_addr = parse_ipv4_str(value);
		else if (action->encap.src_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, action->encap.src_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("encap src ip type is not set, need to set ip type before address");
	} else if (strcmp(field_name, "encap_dst_ip_type") == 0)
		action->encap.dst_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "encap_dst_ip_addr") == 0) {
		if (action->encap.dst_ip.type == DOCA_FLOW_IP4_ADDR)
			action->encap.dst_ip.ipv4_addr = parse_ipv4_str(value);
		else if (action->encap.dst_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, action->encap.dst_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("encap dst ip type is not set, need to set ip type before address");
	} else if (strcmp(field_name, "encap_tun_type") == 0)
		action->encap.tun.type = parse_tun_type_string(value);

	else if (strcmp(field_name, "encap_vxlan_tun_id") == 0)
		action->encap.tun.vxlan_tun_id = strtol(value, NULL, 0);

	else if (strcmp(field_name, "encap_gre_key") == 0)
		action->encap.tun.gre_key = strtol(value, NULL, 0);

	else if (strcmp(field_name, "encap_gtp_teid") == 0)
		action->encap.tun.gtp_teid = strtol(value, NULL, 0);

	else
		DOCA_LOG_ERR("%s is not supported field in actions", field_name);
}

static void
parse_match_field(char *field_name, char *value, void *struct_ptr)
{
	struct doca_flow_match *match = (struct doca_flow_match *)struct_ptr;

	if (strcmp(field_name, "flags") == 0)
		match->flags = (uint32_t)strtol(value, NULL, HEXADECIMAL_BASE);

	else if (strcmp(field_name, "port_meta") == 0) {
		if (strcmp(value, UINT32_CHANGEABLE_FIELD) == 0)
			match->meta.port_meta = UINT32_MAX;
		else
			match->meta.port_meta = (uint32_t)strtol(value, NULL, 0);

	} else if (strcmp(field_name, "out_src_mac") == 0)
		parse_mac_address(value, match->out_src_mac);

	else if (strcmp(field_name, "out_dst_mac") == 0)
		parse_mac_address(value, match->out_dst_mac);

	else if (strcmp(field_name, "out_eth_type") == 0)
		match->out_eth_type = (uint16_t)strtol(value, NULL, HEXADECIMAL_BASE);

	else if (strcmp(field_name, "out_vlan_tci") == 0)
		match->out_vlan_tci = (uint16_t)strtol(value, NULL, 0);

	else if (strcmp(field_name, "out_src_ip_type") == 0)
		match->out_src_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "out_src_ip_addr") == 0) {
		if (match->out_src_ip.type == DOCA_FLOW_IP4_ADDR)
			match->out_src_ip.ipv4_addr = parse_ipv4_str(value);
		else if (match->out_src_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, match->out_src_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("src ip type is not set, need to set ip type before address");

	} else if (strcmp(field_name, "out_dst_ip_type") == 0)
		match->out_dst_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "out_dst_ip_addr") == 0) {
		if (match->out_dst_ip.type == DOCA_FLOW_IP4_ADDR)
			match->out_dst_ip.ipv4_addr = parse_ipv4_str(value);
		else if (match->out_dst_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, match->out_dst_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("dst ip type is not set, need to set ip type before address");

	} else if (strcmp(field_name, "out_l4_type") == 0)
		match->out_l4_type = parse_protocol_string(value);

	else if (strcmp(field_name, "out_tcp_flags") == 0)
		match->out_tcp_flags = parse_tcp_flag_string(value);

	else if (strcmp(field_name, "out_src_port") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			match->out_src_port = UINT16_MAX;
		else
			match->out_src_port = rte_cpu_to_be_16(strtol(value, NULL, 0));

	} else if (strcmp(field_name, "out_dst_port") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			match->out_dst_port = UINT16_MAX;
		else
			match->out_dst_port = rte_cpu_to_be_16(strtol(value, NULL, 0));

	} else if (strcmp(field_name, "tun_type") == 0)
		match->tun.type = parse_tun_type_string(value);

	else if (strcmp(field_name, "vxlan_tun_id") == 0)
		match->tun.vxlan_tun_id = strtol(value, NULL, 0);

	else if (strcmp(field_name, "gre_key") == 0)
		match->tun.gre_key = strtol(value, NULL, 0);

	else if (strcmp(field_name, "gtp_teid") == 0)
		match->tun.gtp_teid = strtol(value, NULL, 0);

	else if (strcmp(field_name, "in_src_mac") == 0)
		parse_mac_address(value, match->in_src_mac);

	else if (strcmp(field_name, "in_dst_mac") == 0)
		parse_mac_address(value, match->in_dst_mac);

	else if (strcmp(field_name, "in_eth_type") == 0)
		match->in_eth_type = (uint16_t)strtol(value, NULL, HEXADECIMAL_BASE);

	else if (strcmp(field_name, "in_vlan_tci") == 0)
		match->in_vlan_tci = (uint16_t)strtol(value, NULL, 0);

	else if (strcmp(field_name, "in_src_ip_type") == 0)
		match->in_src_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "in_src_ip_addr") == 0) {
		if (match->in_src_ip.type == DOCA_FLOW_IP4_ADDR)
			match->in_src_ip.ipv4_addr = parse_ipv4_str(value);
		else if (match->in_src_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, match->in_src_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("inner src ip type is not set, need to set ip type before address");

	} else if (strcmp(field_name, "in_dst_ip_type") == 0)
		match->in_dst_ip.type = parse_ip_type(value);

	else if (strcmp(field_name, "in_dst_ip_addr") == 0) {
		if (match->in_dst_ip.type == DOCA_FLOW_IP4_ADDR)
			match->in_dst_ip.ipv4_addr = parse_ipv4_str(value);
		else if (match->in_dst_ip.type == DOCA_FLOW_IP6_ADDR)
			parse_ipv6_str(value, match->in_dst_ip.ipv6_addr);
		else
			DOCA_LOG_ERR("inner dst ip type is not set, need to set ip type before address");

	} else if (strcmp(field_name, "in_l4_type") == 0)
		match->in_l4_type = parse_protocol_string(value);

	else if (strcmp(field_name, "in_tcp_flags") == 0)
		match->in_tcp_flags = parse_tcp_flag_string(value);

	else if (strcmp(field_name, "in_src_port") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			match->in_src_port = UINT16_MAX;
		else
			match->in_src_port = rte_cpu_to_be_16(strtol(value, NULL, 0));

	} else if (strcmp(field_name, "in_dst_port") == 0) {
		if (strcmp(value, UINT16_CHANGEABLE_FIELD) == 0)
			match->in_dst_port = UINT16_MAX;
		else
			match->in_dst_port = rte_cpu_to_be_16(strtol(value, NULL, 0));
	}

	else
		DOCA_LOG_ERR("%s is not supported field in match", field_name);
}

static void
parse_struct(char *struct_str, void (*fill_struct)(char *, char *, void *), void *struct_ptr)
{
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *tmp;
	char field_name[MAX_FIELD_INPUT_LEN];
	char value[MAX_FIELD_INPUT_LEN];
	char tmp_char;

	do {
		strlcpy(ptr, struct_str, MAX_CMDLINE_INPUT_LEN);
		tmp = strtok(ptr, "=");
		if (tmp == NULL) {
			DOCA_LOG_ERR("Invalid format for create struct command");
			return;
		}
		strlcpy(field_name, tmp, MAX_FIELD_INPUT_LEN);
		struct_str += strlen(field_name) + 1;

		strlcpy(ptr, struct_str, MAX_CMDLINE_INPUT_LEN);
		tmp = strtok(ptr, ",");
		if (tmp == NULL) {
			DOCA_LOG_ERR("Invalid format for create struct command");
			return;
		}
		strlcpy(value, tmp, MAX_FIELD_INPUT_LEN);

		DOCA_LOG_DBG("field_name: %s\tvalue: %s", field_name, value);

		struct_str += strlen(value);
		tmp_char = struct_str[0];
		struct_str++;
		(*fill_struct)(field_name, value, struct_ptr);
	} while (tmp_char == ',');
}

static int
parse_bool_params_input(char **params_str, int param_str_len, bool *take_action)
{
	int value;
	char *ptr;

	*params_str += param_str_len;

	value = strtol(*params_str, &ptr, 0);
	if (ptr == *params_str)
		return -1;
	if (value == 1)
		*take_action = true;
	else if (value != 0)
		return -1;

	*params_str += 1;
	return 0;
}

static int
parse_create_pipe_params(char *params_str, struct doca_flow_pipe_cfg *cfg, bool *fwd_action, bool *fwd_miss_action)
{
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_value;
	char *type_str;
	char *end;
	int value;
	char tmp_char;
	bool has_port_id = false;
	bool take_action = false;

	do {
		if (strncmp(params_str, "port_id=", PORT_ID_STR_LEN) == 0) {
			params_str += PORT_ID_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			value = strtol(ptr, &end, 0);
			if (end == ptr) {
				DOCA_LOG_ERR("Invalid port_id");
				return -1;
			}
			param_str_value = strtok(ptr, ",");
			params_str += strlen(param_str_value);
			pipe_port_id = value;
			has_port_id = true;
		} else if (strncmp(params_str, "name=", NAME_STR_LEN) == 0) {
			if (cfg->attr.name == NULL) {
				params_str += NAME_STR_LEN;
				strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
				param_str_value = strtok(ptr, ",");
				params_str += strlen(param_str_value);
				cfg->attr.name = strndup(param_str_value, MAX_FIELD_INPUT_LEN);
				if (cfg->attr.name == NULL) {
					DOCA_LOG_ERR("failed to allocate memory for name");
					goto error;
				}
			} else
				DOCA_LOG_WARN("Name field is already initialized");
		} else if (strncmp(params_str, "root_enable=", ROOT_ENABLE_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, ROOT_ENABLE_STR_LEN, &take_action);
			if (value < 0) {
				DOCA_LOG_ERR("root_enable must be 1 for using or 0 for not");
				goto error;
			}
			if (take_action)
				cfg->attr.is_root = true;
			take_action = false;
		} else if (strncmp(params_str, "monitor=", MONITOR_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, MONITOR_STR_LEN, &take_action);
			if (value < 0) {
				DOCA_LOG_ERR("monitor must be 1 for using or 0 for not");
				goto error;
			}
			if (take_action)
				cfg->monitor = &monitor;
			take_action = false;
		} else if (strncmp(params_str, "match_mask=", MATCH_MASK_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, MATCH_MASK_STR_LEN, &take_action);
			if (value < 0) {
				DOCA_LOG_ERR("match_mask value must be 1 for using or 0 for not");
				goto error;
			}
			if (take_action)
				cfg->match_mask = &match_mask;
			take_action = false;
		} else if (strncmp(params_str, "fwd_miss=", MISS_FWD_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, MISS_FWD_STR_LEN, fwd_miss_action);
			if (value < 0) {
				DOCA_LOG_ERR("fwd_miss value must be 1 for using or 0 for not");
				goto error;
			}
		} else if (strncmp(params_str, "fwd=", FWD_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, FWD_STR_LEN, fwd_action);
			if (value < 0) {
				DOCA_LOG_ERR("fwd value must be 1 for using or 0 for not");
				goto error;
			}
		} else if (strncmp(params_str, "type=", TYPE_STR_LEN) == 0) {
			params_str += TYPE_STR_LEN;
			strlcpy(ptr, params_str, MAX_FIELD_INPUT_LEN);
			type_str = strtok(ptr, ",");
			cfg->attr.type = parse_pipe_type(type_str);
			params_str += strlen(type_str);
		} else {
			strlcpy(ptr, params_str, MAX_FIELD_INPUT_LEN);
			param_str_value = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for create pipe command", param_str_value);
			goto error;
		}
		tmp_char = params_str[0];
		params_str++;
	} while (tmp_char == ',');

	if (!has_port_id) {
		DOCA_LOG_ERR("port_id is a mandatory input and was not given");
		goto error;
	}
	return 0;
error:
	if (cfg->attr.name != NULL)
		free((void *)cfg->attr.name);
	return -1;
}

static int
parse_add_entry_params(char *params_str, bool *fwd_action, bool *monitor_action, uint64_t *pipe_id, int *pipe_queue)
{
	char tmp_char;
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_name;
	int value;
	bool has_pipe_id = false;
	bool has_pipe_queue = false;

	do {
		if (strncmp(params_str, "pipe_id=", PIPE_ID_STR_LEN) == 0) {
			params_str += PIPE_ID_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			*pipe_id = strtol(ptr, &params_str, 0);
			has_pipe_id = true;
		} else if (strncmp(params_str, "pipe_queue=", PIPE_QUEUE_STR_LEN) == 0) {
			params_str += PIPE_QUEUE_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			*pipe_queue = strtol(ptr, &params_str, 0);
			has_pipe_queue = true;
		} else if (strncmp(params_str, "monitor=", MONITOR_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, MONITOR_STR_LEN, monitor_action);
			if (value < 0) {
				DOCA_LOG_ERR("fwd value must be 1 for using or 0 for not");
				return -1;
			};
		} else if (strncmp(params_str, "fwd=", FWD_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, FWD_STR_LEN, fwd_action);
			if (value < 0) {
				DOCA_LOG_ERR("fwd value must be 1 for using or 0 for not");
				return -1;
			}
			printf("%s\n", params_str);
		} else {
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			param_str_name = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for pipe add entry command", param_str_name);
			return -1;
		}
		tmp_char = params_str[0];
		params_str++;
	} while (tmp_char == ',');

	if (!has_pipe_id) {
		DOCA_LOG_ERR("pipe_id is a mandatory input and was not given");
		return -1;
	}

	if (!has_pipe_queue) {
		DOCA_LOG_ERR("pipe_queue is a mandatory input and was not given");
		return -1;
	}

	return 0;
}

static int
parse_add_control_pipe_entry_params(char *params_str, bool *fwd_action, bool *match_mask_action, uint64_t *pipe_id,
				    uint16_t *pipe_queue, uint8_t *priority)
{
	char tmp_char;
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_name;
	int value;
	bool has_pipe_id = false;
	bool has_pipe_queue = false;
	bool has_priority = false;

	do {
		if (strncmp(params_str, "pipe_id=", PIPE_ID_STR_LEN) == 0) {
			params_str += PIPE_ID_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			*pipe_id = strtol(ptr, &params_str, 0);
			has_pipe_id = true;
		} else if (strncmp(params_str, "pipe_queue=", PIPE_QUEUE_STR_LEN) == 0) {
			params_str += PIPE_QUEUE_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			*pipe_queue = strtol(ptr, &params_str, 0);
			has_pipe_queue = true;
		} else if (strncmp(params_str, "priority=", PRIORITY_STR_LEN) == 0) {
			params_str += PRIORITY_STR_LEN;
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			*priority = strtol(ptr, &params_str, 0);
			has_priority = true;
		} else if (strncmp(params_str, "match_mask=", MATCH_MASK_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, MATCH_MASK_STR_LEN, match_mask_action);
			if (value < 0) {
				DOCA_LOG_ERR("match_mask value must be 1 for using or 0 for not");
				return -1;
			};
		} else if (strncmp(params_str, "fwd=", FWD_STR_LEN) == 0) {
			value = parse_bool_params_input(&params_str, FWD_STR_LEN, fwd_action);
			if (value < 0) {
				DOCA_LOG_ERR("fwd value must be 1 for using or 0 for not");
				return -1;
			}
		} else {
			strlcpy(ptr, params_str, MAX_CMDLINE_INPUT_LEN);
			param_str_name = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for control pipe add entry command", param_str_name);
			return -1;
		}
		tmp_char = params_str[0];
		params_str++;
	} while (tmp_char == ',');

	if (!has_pipe_id) {
		DOCA_LOG_ERR("pipe_id is a mandatory input and was not given");
		return -1;
	}

	if (!has_pipe_queue) {
		DOCA_LOG_ERR("pipe_queue is a mandatory input and was not given");
		return -1;
	}

	if (!has_priority) {
		DOCA_LOG_ERR("priority is a mandatory input and was not given");
		return -1;
	}
	return 0;
}

static int
parse_destroy_pipe_params(char *params, uint16_t *port_id, uint64_t *pipe_id)
{
	char tmp_char;
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_name;
	bool has_port_id = false;
	bool has_pipe_id = false;

	do {
		if (strncmp(params, "port_id=", PORT_ID_STR_LEN) == 0) {
			params += PORT_ID_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			*port_id = strtol(ptr, &params, 0);
			has_port_id = true;
		} else if (strncmp(params, "pipe_id=", PIPE_ID_STR_LEN) == 0) {
			params += PIPE_ID_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			*pipe_id = strtol(ptr, &params, 0);
			has_pipe_id = true;
		} else {
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			param_str_name = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for destroy pipe command", param_str_name);
			return -1;
		}
		tmp_char = params[0];
		params++;
	} while (tmp_char == ',');

	if (!has_port_id) {
		DOCA_LOG_ERR("port_id is a mandatory input and was not given");
		return -1;
	}

	if (!has_pipe_id) {
		DOCA_LOG_ERR("pipe_id is a mandatory input and was not given");
		return -1;
	}
	return 0;
}

static int
parse_entry_params(char *params, uint16_t *pipe_queue, uint64_t *entry_id, bool pipe_queue_mandatory)
{
	char tmp_char;
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_name;
	bool has_pipe_queue = false;
	bool has_entry_id = false;

	do {
		if (strncmp(params, "pipe_queue=", PIPE_QUEUE_STR_LEN) == 0) {
			params += PIPE_QUEUE_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			if (pipe_queue != NULL)
				*pipe_queue = strtol(ptr, &params, 0);
			has_pipe_queue = true;
		} else if (strncmp(params, "entry_id=", ENTRY_ID_STR_LEN) == 0) {
			params += ENTRY_ID_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			*entry_id = strtol(ptr, &params, 0);
			has_entry_id = true;
		} else {
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			param_str_name = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for rm/query entry command", param_str_name);
			return -1;
		}
		tmp_char = params[0];
		params++;
	} while (tmp_char == ',');

	if (pipe_queue_mandatory && !has_pipe_queue) {
		DOCA_LOG_ERR("pipe_queue is a mandatory input and was not given");
		return -1;
	}

	if (!has_entry_id) {
		DOCA_LOG_ERR("entry_id is a mandatory input and was not given");
		return -1;
	}
	return 0;
}

static int
parse_dump_pipe_params(char *params, uint16_t *port_id, FILE **file)
{
	char tmp_char;
	char *name;
	char ptr[MAX_CMDLINE_INPUT_LEN];
	char *param_str_name;
	bool has_port_id = false;
	bool has_file = false;

	do {
		if (strncmp(params, "port_id=", PORT_ID_STR_LEN) == 0) {
			params += PORT_ID_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			*port_id = strtol(ptr, &params, 0);
			has_port_id = true;
		} else if (strncmp(params, "file=", FILE_STR_LEN) == 0) {
			if (has_file) {
				DOCA_LOG_ERR("file should be provided only once");
				fclose(*file);
				return -1;
			}
			params += FILE_STR_LEN;
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			name = strtok(ptr, ",");
			params += strlen(name);
			*file = fopen(name, "w");
			if (*file == NULL) {
				DOCA_LOG_ERR("failed opening the file %s", name);
				return -1;
			}
			has_file = true;
		} else {
			strlcpy(ptr, params, MAX_CMDLINE_INPUT_LEN);
			param_str_name = strtok(ptr, "=");
			DOCA_LOG_ERR("%s is not a valid parameter for port pipes dump command", param_str_name);
			return -1;
		}
		tmp_char = params[0];
		params++;
	} while (tmp_char == ',');

	if (!has_port_id) {
		DOCA_LOG_ERR("port_id is a mandatory input and was not given");
		return -1;
	}

	if (!has_file) {
		DOCA_LOG_DBG("file name was not given, default name is port_info.txt");
		*file = fopen("port_info.txt", "w");
		if (*file == NULL) {
			DOCA_LOG_ERR("failed opening the file port_info.txt");
			return -1;
		}
	}
	return 0;
}

static void
cmd_create_pipe_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_create_pipe_result *create_pipe_data = (struct cmd_create_pipe_result *)parsed_result;
	struct doca_flow_fwd *tmp_fwd = NULL;
	struct doca_flow_fwd *tmp_fwd_miss = NULL;
	struct doca_flow_pipe_cfg pipe_cfg = {.match = &pipe_match};
	struct doca_flow_actions *actions_arr[1];
	bool is_fwd = false;
	bool is_fwd_miss = false;
	int ret;

	if (create_pipe_func == NULL) {
		DOCA_LOG_ERR("Pipe creation action was not inserted");
		return;
	}

	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	ret = parse_create_pipe_params(create_pipe_data->params, &pipe_cfg, &is_fwd, &is_fwd_miss);
	if (ret < 0)
		return;

	if (is_fwd)
		tmp_fwd = &fwd;

	if (is_fwd_miss)
		tmp_fwd_miss = &fwd_miss;

	(*create_pipe_func)(&pipe_cfg, pipe_port_id, tmp_fwd, fwd_next_pipe_id, tmp_fwd_miss, fwd_miss_next_pipe_id);
}

cmdline_parse_token_string_t cmd_create_pipe_create_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_pipe_result, create, "create");

cmdline_parse_token_string_t cmd_create_pipe_pipe_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_pipe_result, pipe, "pipe");

cmdline_parse_token_string_t cmd_create_pipe_optional_fields_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_pipe_result, params, NULL);

cmdline_parse_inst_t cmd_create_pipe = {
	.f = cmd_create_pipe_parsed, /* function to call */
	.data = NULL,		     /* 2nd arg of func */
	.help_str = "create pipe port_id=[port_id],[optional params]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_create_pipe_create_tok,
			(void *)&cmd_create_pipe_pipe_tok,
			(void *)&cmd_create_pipe_optional_fields_tok,
			NULL,
		},
};

static void
cmd_add_entry_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_add_entry_result *add_entry_data = (struct cmd_add_entry_result *)parsed_result;
	struct doca_flow_fwd *tmp_fwd = NULL;
	struct doca_flow_monitor *tmp_monitor = NULL;
	bool is_fwd = false;
	bool is_monitor = false;
	uint64_t pipe_id = 0;
	int pipe_queue = 0;
	int ret;

	if (add_entry_func == NULL) {
		DOCA_LOG_ERR("Entry creation action was not inserted");
		return;
	}

	ret = parse_add_entry_params(add_entry_data->params, &is_fwd, &is_monitor, &pipe_id, &pipe_queue);
	if (ret < 0)
		return;

	if (is_fwd)
		tmp_fwd = &fwd;

	if (is_monitor)
		tmp_monitor = &monitor;

	(*add_entry_func)(pipe_queue, pipe_id, &entry_match, &actions, tmp_monitor, tmp_fwd, fwd_next_pipe_id,
			  DOCA_FLOW_NO_WAIT);
}

cmdline_parse_token_string_t cmd_add_entry_add_tok = TOKEN_STRING_INITIALIZER(struct cmd_add_entry_result, add, "add");

cmdline_parse_token_string_t cmd_add_entry_entry_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_entry_result, entry, "entry");

cmdline_parse_token_string_t cmd_add_entry_optional_fields_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_entry_result, params, NULL);

cmdline_parse_inst_t cmd_add_entry = {
	.f = cmd_add_entry_parsed, /* function to call */
	.data = NULL,		   /* 2nd arg of func */
	.help_str = "add entry pipe_id=[pipe_id],pipe_queue=[pipe_queue],[optional fields]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_add_entry_add_tok,
			(void *)&cmd_add_entry_entry_tok,
			(void *)&cmd_add_entry_optional_fields_tok,
			NULL,
		},
};

static void
cmd_add_control_pipe_entry_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_add_control_pipe_entry_result *add_entry_data =
		(struct cmd_add_control_pipe_entry_result *)parsed_result;
	struct doca_flow_fwd *tmp_fwd = NULL;
	struct doca_flow_match *tmp_match_mask = NULL;
	bool is_fwd = false;
	bool is_match_mask = false;
	uint64_t pipe_id = 0;
	uint16_t pipe_queue = 0;
	uint8_t priority = 0;
	int ret;

	if (add_control_pipe_entry_func == NULL) {
		DOCA_LOG_ERR("Control pipe entry creation action was not inserted");
		return;
	}

	ret = parse_add_control_pipe_entry_params(add_entry_data->params, &is_fwd, &is_match_mask, &pipe_id,
						  &pipe_queue, &priority);
	if (ret < 0)
		return;

	if (is_fwd)
		tmp_fwd = &fwd;
	if (is_match_mask)
		tmp_match_mask = &match_mask;

	(*add_control_pipe_entry_func)(pipe_queue, priority, pipe_id, &entry_match, tmp_match_mask, tmp_fwd,
				       fwd_next_pipe_id);
}

cmdline_parse_token_string_t cmd_add_control_pipe_entry_add_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_control_pipe_entry_result, add, "add");

cmdline_parse_token_string_t cmd_add_control_pipe_entry_control_pipe_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_control_pipe_entry_result, control_pipe, "control_pipe");

cmdline_parse_token_string_t cmd_add_control_pipe_entry_entry_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_control_pipe_entry_result, entry, "entry");

cmdline_parse_token_string_t cmd_add_control_pipe_entry_optional_fields_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_add_control_pipe_entry_result, params, NULL);

cmdline_parse_inst_t cmd_add_control_pipe_entry = {
	.f = cmd_add_control_pipe_entry_parsed, /* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str =
		"add control_pipe entry priority=[priority],port_id=[port_id],pipe_id=[pipe_id],pipe_queue=[pipe_queue],[optional fields]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_add_control_pipe_entry_add_tok,
			(void *)&cmd_add_control_pipe_entry_control_pipe_tok,
			(void *)&cmd_add_control_pipe_entry_entry_tok,
			(void *)&cmd_add_control_pipe_entry_optional_fields_tok,
			NULL,
		},
};

static void
cmd_destroy_pipe_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_destroy_pipe_result *destroy_pipe_data = (struct cmd_destroy_pipe_result *)parsed_result;
	uint16_t port_id = 0;
	uint64_t pipe_id = 0;
	int ret;

	if (destroy_pipe_func == NULL) {
		DOCA_LOG_ERR("Pipe destruction action was not inserted");
		return;
	}

	ret = parse_destroy_pipe_params(destroy_pipe_data->params, &port_id, &pipe_id);
	if (ret < 0)
		return;

	(*destroy_pipe_func)(port_id, pipe_id);
}

cmdline_parse_token_string_t cmd_destroy_pipe_destroy_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_destroy_pipe_result, destroy, "destroy");

cmdline_parse_token_string_t cmd_destroy_pipe_pipe_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_destroy_pipe_result, pipe, "pipe");

cmdline_parse_token_string_t cmd_destroy_pipe_params_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_destroy_pipe_result, params, NULL);

cmdline_parse_inst_t cmd_destroy_pipe = {
	.f = cmd_destroy_pipe_parsed, /* function to call */
	.data = NULL,		      /* 2nd arg of func */
	.help_str = "destroy pipe port_id=[port_id],pipe_id=[pipe_id]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_destroy_pipe_destroy_tok,
			(void *)&cmd_destroy_pipe_pipe_tok,
			(void *)&cmd_destroy_pipe_params_tok,
			NULL,
		},
};

static void
cmd_rm_entry_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_rm_entry_result *rm_entry_data = (struct cmd_rm_entry_result *)parsed_result;
	uint64_t entry_id = 0;
	uint16_t pipe_queue = 0;
	int ret;

	if (remove_entry_func == NULL) {
		DOCA_LOG_ERR("Entry destruction action was not inserted");
		return;
	}

	ret = parse_entry_params(rm_entry_data->params, &pipe_queue, &entry_id, true);
	if (ret < 0)
		return;

	(*remove_entry_func)(pipe_queue, entry_id);
}

cmdline_parse_token_string_t cmd_rm_entry_rm_tok = TOKEN_STRING_INITIALIZER(struct cmd_rm_entry_result, rm, "rm");

cmdline_parse_token_string_t cmd_rm_entry_entry_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_rm_entry_result, entry, "entry");

cmdline_parse_token_string_t cmd_rm_entry_params_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_rm_entry_result, params, NULL);

cmdline_parse_inst_t cmd_rm_entry = {
	.f = cmd_rm_entry_parsed, /* function to call */
	.data = NULL,		  /* 2nd arg of func */
	.help_str = "rm entry pipe_queue=[pipe_queue],entry_id=[entry_id]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_rm_entry_rm_tok,
			(void *)&cmd_rm_entry_entry_tok,
			(void *)&cmd_rm_entry_params_tok,
			NULL,
		},
};

static void
cmd_flush_pipes_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_flush_pipes_result *flush_pipes_data = (struct cmd_flush_pipes_result *)parsed_result;
	uint16_t port_id;
	int res;

	if (port_pipes_flush_func == NULL) {
		DOCA_LOG_ERR("Pipes flushing action was not inserted");
		return;
	}

	res = parse_port_id_input(flush_pipes_data->port_id);
	if (res < 0)
		return;

	port_id = res;
	(*port_pipes_flush_func)(port_id);
}

cmdline_parse_token_string_t cmd_flush_pipes_port_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_pipes_result, port, "port");

cmdline_parse_token_string_t cmd_flush_pipes_pipes_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_pipes_result, pipes, "pipes");

cmdline_parse_token_string_t cmd_flush_pipes_flush_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_pipes_result, flush, "flush");

cmdline_parse_token_string_t cmd_flush_pipes_port_id_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flush_pipes_result, port_id, NULL);

cmdline_parse_inst_t cmd_flush_pipe = {
	.f = cmd_flush_pipes_parsed, /* function to call */
	.data = NULL,		     /* 2nd arg of func */
	.help_str = "port pipes flush port_id=[port_id]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_flush_pipes_port_tok,
			(void *)&cmd_flush_pipes_pipes_tok,
			(void *)&cmd_flush_pipes_flush_tok,
			(void *)&cmd_flush_pipes_port_id_tok,
			NULL,
		},
};

static void
cmd_query_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_query_result *query_data = (struct cmd_query_result *)parsed_result;
	struct doca_flow_query query_stats;
	uint64_t entry_id = 0;
	int ret;

	if (query_func == NULL) {
		DOCA_LOG_ERR("Query action was not inserted");
		return;
	}

	ret = parse_entry_params(query_data->params, NULL, &entry_id, false);
	if (ret < 0)
		return;

	(*query_func)(entry_id, &query_stats);

	DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
	DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);
}

cmdline_parse_token_string_t cmd_query_query_tok = TOKEN_STRING_INITIALIZER(struct cmd_query_result, query, "query");

cmdline_parse_token_string_t cmd_query_params_tok = TOKEN_STRING_INITIALIZER(struct cmd_query_result, params, NULL);

cmdline_parse_inst_t cmd_query = {
	.f = cmd_query_parsed, /* function to call */
	.data = NULL,	       /* 2nd arg of func */
	.help_str = "query entry_id=[entry_id]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_query_query_tok,
			(void *)&cmd_query_params_tok,
			NULL,
		},
};

static void
cmd_dump_pipe_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_dump_pipe_result *dump_pipe_data = (struct cmd_dump_pipe_result *)parsed_result;
	uint16_t port_id = 0;
	FILE *fd = NULL;
	int ret;

	if (port_pipes_dump_func == NULL) {
		DOCA_LOG_ERR("Pipe dumping action was not inserted");
		return;
	}

	ret = parse_dump_pipe_params(dump_pipe_data->params, &port_id, &fd);
	if (ret < 0) {
		if (fd)
			fclose(fd);
		return;
	}

	(*port_pipes_dump_func)(port_id, fd);

	fclose(fd);
}

cmdline_parse_token_string_t cmd_port_pipes_dump_port_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_pipe_result, port, "port");

cmdline_parse_token_string_t cmd_port_pipes_dump_pipes_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_pipe_result, pipes, "pipes");

cmdline_parse_token_string_t cmd_port_pipes_dump_dump_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_pipe_result, dump, "dump");

cmdline_parse_token_string_t cmd_dump_pipe_params_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_dump_pipe_result, params, NULL);

cmdline_parse_inst_t cmd_dump_pipe = {
	.f = cmd_dump_pipe_parsed, /* function to call */
	.data = NULL,		   /* 2nd arg of func */
	.help_str = "port pipes dump port_id=[port_id],file=[file name]",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_port_pipes_dump_port_tok,
			(void *)&cmd_port_pipes_dump_pipes_tok,
			(void *)&cmd_port_pipes_dump_dump_tok,
			(void *)&cmd_dump_pipe_params_tok,
			NULL,
		},
};

static void
cmd_create_struct_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_create_struct_result *struct_data = (struct cmd_create_struct_result *)parsed_result;

	if (strcmp(struct_data->flow_struct, "pipe_match") == 0) {
		memset(&pipe_match, 0, sizeof(pipe_match));
		parse_struct(struct_data->flow_struct_input, &parse_match_field, (void *)&pipe_match);
	} else if (strcmp(struct_data->flow_struct, "entry_match") == 0) {
		memset(&entry_match, 0, sizeof(entry_match));
		parse_struct(struct_data->flow_struct_input, &parse_match_field, (void *)&entry_match);
	} else if (strcmp(struct_data->flow_struct, "match_mask") == 0) {
		memset(&match_mask, 0, sizeof(match_mask));
		parse_struct(struct_data->flow_struct_input, &parse_match_field, (void *)&match_mask);
	} else if (strcmp(struct_data->flow_struct, "actions") == 0) {
		memset(&actions, 0, sizeof(actions));
		parse_struct(struct_data->flow_struct_input, &parse_actions_field, (void *)&actions);
	} else if (strcmp(struct_data->flow_struct, "monitor") == 0) {
		memset(&monitor, 0, sizeof(monitor));
		parse_struct(struct_data->flow_struct_input, &parse_monitor_field, (void *)&monitor);
	} else if (strcmp(struct_data->flow_struct, "fwd") == 0) {
		memset(&fwd, 0, sizeof(fwd));
		parse_struct(struct_data->flow_struct_input, &parse_fwd_field, (void *)&fwd);
	} else if (strcmp(struct_data->flow_struct, "fwd_miss") == 0) {
		memset(&fwd_miss, 0, sizeof(fwd_miss));
		parse_struct(struct_data->flow_struct_input, &parse_fwd_miss_field, (void *)&fwd_miss);
	}
}

cmdline_parse_token_string_t cmd_create_struct_update_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_struct_result, create, "create");

cmdline_parse_token_string_t cmd_create_struct_struct_tok = TOKEN_STRING_INITIALIZER(
	struct cmd_create_struct_result, flow_struct, "pipe_match#entry_match#match_mask#actions#monitor#fwd#fwd_miss");

cmdline_parse_token_string_t cmd_create_struct_input_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_struct_result, flow_struct_input, TOKEN_STRING_MULTI);

cmdline_parse_inst_t cmd_update_struct = {
	.f = cmd_create_struct_parsed, /* function to call */
	.data = NULL,		       /* 2nd arg of func */
	.help_str = "create pipe_match|entry_match|match_mask|actions|monitor|fwd|fwd_miss <struct fields>",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_create_struct_update_tok,
			(void *)&cmd_create_struct_struct_tok,
			(void *)&cmd_create_struct_input_tok,
			NULL,
		},
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_tok = TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed, /* function to call */
	.data = NULL,	      /* 2nd arg of func */
	.help_str = "Exit application",
	.tokens = {
			/* token list, NULL terminated */
			(void *)&cmd_quit_tok,
			NULL,
		},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_update_struct,
	(cmdline_parse_inst_t *)&cmd_create_pipe,
	(cmdline_parse_inst_t *)&cmd_add_entry,
	(cmdline_parse_inst_t *)&cmd_add_control_pipe_entry,
	(cmdline_parse_inst_t *)&cmd_destroy_pipe,
	(cmdline_parse_inst_t *)&cmd_rm_entry,
	(cmdline_parse_inst_t *)&cmd_flush_pipe,
	(cmdline_parse_inst_t *)&cmd_dump_pipe,
	(cmdline_parse_inst_t *)&cmd_query,
	NULL,
};

int
flow_parser_init(char *shell_prompt)
{
	struct cmdline *cl;

	reset_doca_flow_structs();

	cl = cmdline_stdin_new(main_ctx, shell_prompt);
	if (cl == NULL)
		return -1;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	return 0;
}

void
flow_parser_cleanup()
{
	if (rss_queues)
		free(rss_queues);
}
