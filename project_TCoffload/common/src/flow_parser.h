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

#ifndef COMMON_FLOW_PARSER_H_
#define COMMON_FLOW_PARSER_H_

#include <doca_flow.h>

#include "utils.h"

doca_be32_t parse_ipv4_str(const char *str_ip);

uint8_t parse_protocol_string(const char *protocol_str);

void set_action_on_pipe_creation(void (*action)(struct doca_flow_pipe_cfg *cfg, uint16_t port_id,
						struct doca_flow_fwd *fwd, uint64_t fw_pipe_id,
						struct doca_flow_fwd *fwd_miss, uint64_t fw_miss_pipe_id));

void set_action_on_entry_creation(void (*action)(uint16_t pipe_queue, uint64_t pipe_id,
						 struct doca_flow_match *match, struct doca_flow_actions *actions,
						 struct doca_flow_monitor *monitor,
						 struct doca_flow_fwd *fwd, uint64_t fw_pipe_id,
						 uint32_t flags));

void set_action_on_control_pipe_entry_creation(void (*action)(uint16_t pipe_queue, uint8_t priority, uint64_t pipe_id,
						 struct doca_flow_match *match, struct doca_flow_match *match_mask,
						 struct doca_flow_fwd *fwd, uint64_t fw_pipe_id));

void set_action_on_pipe_destruction(void (*action)(uint16_t port_id, uint64_t pipe_id));

void set_action_on_entry_removal(void (*action)(uint16_t pipe_queue, uint64_t entry_id));

void set_action_on_port_pipes_flushing(void (*action)(uint16_t port_id));

void set_action_on_query(void (*action)(uint64_t entry_id, struct doca_flow_query *states));

void set_action_on_port_pipes_dumping(void (*action)(uint16_t port_id, FILE *fd));

int flow_parser_init(char *shell_prompt);

void flow_parser_cleanup(void);

#endif //COMMON_FLOW_PARSER_H_
