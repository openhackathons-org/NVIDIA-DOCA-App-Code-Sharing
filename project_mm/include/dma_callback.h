#include <assert.h>

#define DMA_WORKQ_SIZE 400

#define INVALID_CB_IDX_DATA 0xffff

#define DMA_CB_F_NONE 0
#define DMA_CB_F_NULL 0x1
#define DMA_CB_F_V1 0x2
#define DMA_CB_F_V2 0x3
#define DMA_CB_F_ADD_CACHE_G 0x4
#define DMA_CB_F_MUSK 0xf

#define DMA_ASYNC 0x00
#define DMA_SYNC 0x10

struct DMA_CB_ST
{
    unsigned long x86;
    unsigned long arm;
    unsigned int size;
    unsigned int flag;
};

struct DMA_WKQ_ST
{
    unsigned int idx_ed;
    unsigned int idx_st;
    struct DMA_CB_ST dma_cb[DMA_WORKQ_SIZE];
};
