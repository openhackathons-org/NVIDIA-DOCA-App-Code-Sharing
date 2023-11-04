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

#ifndef LOG_FORWARDER_H_
#define LOG_FORWARDER_H_

#include <condition_variable>
#include <grpcpp/grpcpp.h>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "common.grpc.pb.h"

struct synchronized_queue {
	std::mutex queue_lock;
	std::condition_variable cond_has_records;
	std::queue< std::string > pending_records;
};

struct clients_pool {
	std::mutex lock;
	std::vector< std::pair<grpc::ServerWriter< LogRecord > *, std::condition_variable * > > pool;
};

void synchronized_queue_block_until_has_logs(struct synchronized_queue *queue);

std::string synchronized_queue_dequeue(struct synchronized_queue *queue);

void synchronized_queue_enqueue(struct synchronized_queue *queue, std::string msg);

void forward_log_records(struct synchronized_queue *queue, struct clients_pool *clients);

bool subscribe_client(struct clients_pool *clients, grpc::ServerWriter< LogRecord > *writer);

void teardown_server_sessions(struct synchronized_queue *queue, struct clients_pool *clients);

#endif /* LOG_FORWARDER_H_ */
