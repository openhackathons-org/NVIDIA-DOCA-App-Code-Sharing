#ifndef DMA_FUNC_H
#define DMA_FUNC_H

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <doca_buf.h>
#include "config.h"
#include <pthread.h>
#include "ofd_info.h"

// TODO maybe I can merge the dma_func and the dma_com files

struct R_DMA_OBJ
{
	unsigned long addr;
	unsigned int len;
	unsigned int des_len;
	unsigned int vhca_id;
	unsigned int mkey;
	unsigned int page_size;
	unsigned int not_use;
};

#define EXPORT_STR_FORMAT "{\"vhca_id\":%d,\"access_key\":[%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu,%hhu],\"mchunk\":{\"addr\":%ld,\"len\":%d,\"mkey\":%d,\"page_size\":%d}}\x00"
#define EXPORT_MMAP_DATA_TRANS_LEN 40
void unfold_export_str_data(uint8_t *ex_s, size_t export_str_len, struct R_DMA_OBJ *obj);
void encapsulate_export_str_data(uint8_t *out, uint8_t *ex_s, struct R_DMA_OBJ *obj);

bool init_dma_client();
bool gen_dma_map_range_export_json(char *src_buffer, size_t length, uint8_t **export_str, size_t *export_str_len);

bool gen_memory_range_from_export_json(char *export_json);
bool init_dma_server(uint32_t max_chunks);
bool gen_dma_buf_export_json(char *src_buffer, size_t length, uint8_t **export_str, size_t *export_str_len);
bool init_share_com_doca_buf(char *remtoe_addr, char *local_addr, size_t lens);

void init_doca_job();
bool sync_to(size_t lens);
bool sync_from(size_t lens);

bool gen_dma_map_range_export_json_client(char *src_buffer, size_t length, uint8_t **export_str, size_t *export_str_len, int permission);

// todo merge those two function
void handle_memory_client(char *addr);
void handle_memory_client2(char *addr, struct ofd_contrl_msg *ofd_msg);

#define MAX_DOCA_BUF_BUF_COUNT 0x10

struct doca_buf_list
{
	struct doca_buf *doca_buf_pointer[MAX_DOCA_BUF_BUF_COUNT];
	unsigned long addr;
	unsigned int count;
	unsigned int turn;
};
struct mmap_range_list
{
	unsigned long st_addr;
	unsigned long ed_addr;
	struct doca_mmap *mmap;
	struct doca_buf_list *doca_buf_head;
	struct mmap_range_list *next;
};

struct mmap_range_list *get_remote_mmap_range_by_addr(unsigned long addr);
bool doca_mem_copy_operate(struct doca_buf *src_doca_buf, struct doca_buf *dst_doca_buf, size_t copy_size, bool is_now);
bool doca_mem_copy_from(struct doca_buf_list *remote_dob, unsigned long x86_addr, char *arm_addr, size_t copy_size, int is_now);
bool doca_mem_copy_to(struct doca_buf_list *remote_dob, unsigned long x86_addr, char *arm_addr, size_t copy_size, bool is_now);
void doca_mem_copy_to_sync(struct doca_buf_list *remote_dob, unsigned long x86_addr, char *arm_addr, size_t copy_size);
struct doca_buf_list *get_r_doca_buf_list(unsigned long remote_addr, size_t count);
void *get_doca_buf_pointer_in_dpu(unsigned long addr, unsigned long size);
void setup_ring_info_init(unsigned long read_ring_addr, unsigned long ring_ed_inv_addr, unsigned long ring_st_inv_addr, unsigned long ep_en_ring_addr, unsigned long write_ring_addr);

extern char (*d_read_buf_ring)[READ_BUF_SIZE];
extern char *d_write_buf_ring;
extern struct RING_INFO_ED *d_ring_ed_inv;
extern struct RING_INFO_ST *d_ring_st_inv;
extern struct EP_EVENT_ARM *d_ep_en_ring;
extern struct ofd_contrl_msg *d_ofd_code_addr;
extern struct ofd_contrl_msg *d_ofd_code_addr2;
extern char (*off_thread_write_buf_arr)[W_BUF_S_ONCE];
bool sync_read_buf_to(int qid,unsigned int offset, unsigned int size);
bool sync_write_buf_from(unsigned int offset, unsigned int size, bool is_now);
bool sync_write_buf_to(unsigned int offset, unsigned int size, bool is_now);
bool sync_ep_en_ring_to(unsigned int offset, unsigned int count);
bool sync_ring_ed_inv_to(int count, bool sync_flag);
bool sync_ring_st_inv_from(int count, bool sync_flag);
void barrier_finish_all_doca();
void init_ofd_code_msg(unsigned long r_ofd_code_msg_addr);
void sync_ofd_msg_from(size_t lens);
void sync_ofd_msg_to(size_t lens);
void sync_ofd_msg_from2(size_t lens);
void sync_ofd_msg_to2(size_t lens);
unsigned long get_dma_speed();

// char *GLOABL_MEM_POOL;

void allocate_dpu_mmap_mem_pool();
char *malloc_mem_pool(size_t size);
void sync_write_buf_from_now(unsigned int size);
struct core_objects *get_core_object();


#endif
