#ifndef CC_CHANNEL
#define CC_CHANNEL
#include <stdbool.h>
#include <unistd.h>
#include "dma_com.h"

bool open_comm_channel_client();
bool open_comm_channel_server();
// server and client are same
bool close_comm_channel();
size_t read_comm_channel(void *buf, size_t max_len);
size_t write_comm_channel(void *buf, size_t len);

#endif
