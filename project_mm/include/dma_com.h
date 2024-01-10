#ifndef DMA_COMMON_H_
#define DMA_COMMON_H_

#include <doca_error.h>
#include <stddef.h>
#include <stdint.h>

struct core_objects
{
	struct doca_dev *dev;
	struct doca_dev_rep* cc_dev_rep;
	struct doca_mmap *mmap;
	struct doca_buf_inventory *buf_inv;
	struct doca_ctx *ctx;
	struct doca_dma *dma_ctx;
	struct doca_workq *workq;
	
};

doca_error_t open_local_device(const char *pcie_addr, struct core_objects *state);
doca_error_t create_server_core_objects(struct core_objects *state);
doca_error_t init_server_core_objects(struct core_objects *state, uint32_t max_chunks);
doca_error_t init_client_core_objects(struct core_objects *state, const uint32_t max_chunks);
doca_error_t populate_mmap(struct doca_mmap *mmap, char *buffer, size_t length, size_t pg_sz);
void cleanup_server_core_objects(struct core_objects *state);
void destroy_server_core_objects(struct core_objects *state);
void destroy_client_core_objects(struct core_objects *state);
doca_error_t client_create_dma_mmap(struct doca_dev *dev, struct doca_mmap **mmap, int permission);

#endif


