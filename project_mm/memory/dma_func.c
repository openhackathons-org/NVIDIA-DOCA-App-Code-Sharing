#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>

#include <doca_mmap.h>
#include <sys/mman.h> //mmap
#include <sys/stat.h>

#include <fcntl.h> // O_RDWR

#include <netdb.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>

#include "dma_func.h"
#include "utils.h"
#include "config.h"
#include "dma_com.h"
#include "elf_func.h"

// mansure clock cycles counts variation in AArch64(Cortex A53)
#include <sys/time.h>
#include <assert.h>
#include <pthread.h>
#include <malloc.h>
#include <stdatomic.h>

#include "dma_callback.h"

#define SET_DOCA_BUF_COPY_LEN(s_doca_buf, len) ((uint64_t *)(s_doca_buf))[3] = (len)

// #define SET_DOCA_BUF_ADDR(doca_buf_ptr, addr, count) \
// 	((unsigned long *)doca_buf_ptr)[0] = addr;       \
// 	((unsigned long *)doca_buf_ptr)[1] = (unsigned long)count;

#define SET_DOCA_BUF_ADDR(s_doca_buf, addr) ((uint64_t *)(s_doca_buf))[2] = (addr)

#define DOCA_BUF_APPLY(addr, len, inv_dob)                                                                               \
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, addr, len, &inv_dob);                                \
	if (res != DOCA_SUCCESS)                                                                                             \
	{                                                                                                                    \
		error("Unable to acquire " #inv_dob " DOCA buffer representing local buffer: %s\n", doca_get_error_string(res)); \
	}

#define DOCA_BUF_SET_INFO(s_doca_buf, addr, len)                                     \
	res = doca_buf_set_data(s_doca_buf, addr, len);                                  \
	if (res != DOCA_SUCCESS)                                                         \
	{                                                                                \
		error("Failed to set data for DOCA buffer: %s", doca_get_error_string(res)); \
	}

#define DOCA_BUF_APPLY_FOR_REMOTE(addr, len, inv_dob)                                                                 \
	remtoe_mmap_range = get_remote_mmap_range_by_addr(addr);                                                          \
	if (remtoe_mmap_range == NULL)                                                                                    \
	{                                                                                                                 \
		error("remote mmap range is not ready" #addr " error addr(%p)\n", addr);                                      \
	}                                                                                                                 \
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, remtoe_mmap_range->mmap, addr, len, &inv_dob);                \
	if (res != DOCA_SUCCESS)                                                                                          \
	{                                                                                                                 \
		error("Unable to acquire" #addr " DOCA buffer representing remtoe buffer: %s\n", doca_get_error_string(res)); \
	}

char *GLOABL_MEM_POOL = NULL;
char *GLOABL_MEM_POOL_FREE = NULL;
volatile struct CMD_MSG *sync_ctrl_cmd = NULL;
static struct mmap_range_list *mmap_range_head = NULL;
static struct doca_mmap *remote_mmap = NULL;
static struct core_objects state = {0};
static struct doca_buf *remote_share_doca_buf = NULL;
static struct doca_buf *local_share_doca_buf = NULL;
// todo change
static struct doca_buf *arm_global_dob[MAX_DOCA_BUF_BUF_COUNT];
static int turn_arm = 0;

struct core_objects *get_core_object()
{
	return &state;
}

void allocate_dpu_mmap_mem_pool()
{
	// TODO : use 2MB hugepage
	// GLOABL_MEM_POOL = malloc(DPU_MEM_POOL_SIZE);
	GLOABL_MEM_POOL = mmap(NULL, DPU_MEM_POOL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB, -1, 0);
	assert(GLOABL_MEM_POOL != MAP_FAILED);
	debug("mmap hugepage addr(%#lx) len(%#x)\n", GLOABL_MEM_POOL, DPU_MEM_POOL_SIZE);
	GLOABL_MEM_POOL_FREE = (char *)((((unsigned long)GLOABL_MEM_POOL + PAGE_SIZE - 1) >> 12) << 12);
	debug4("GLOABL_MEM_POOL (%p) GLOABL_MEM_POOL_FREE(%p), size(0x%x)\n", GLOABL_MEM_POOL, GLOABL_MEM_POOL_FREE, DPU_MEM_POOL_SIZE);
	assert(GLOABL_MEM_POOL != NULL);
	// ? don't need mlock memory, maybe doca api can do it
	// mlock(GLOABL_MEM_POOL, DPU_MEM_POOL_SIZE);
	if (populate_mmap(state.mmap, GLOABL_MEM_POOL, DPU_MEM_POOL_SIZE, PAGE_SIZE) != DOCA_SUCCESS)
	{
		error("allocate and populate mmap mempool in DPU is error st(%#lx)-ed(%#lx)\n", GLOABL_MEM_POOL, GLOABL_MEM_POOL + DPU_MEM_POOL_SIZE);
		exit(0);
	}
	for (int i = 0; i < MAX_DOCA_BUF_BUF_COUNT; i++)
	{
		doca_error_t res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, GLOABL_MEM_POOL, DPU_MEM_POOL_SIZE, &arm_global_dob[i]);
		if (res != DOCA_SUCCESS)
		{
			error("Unable to acquire DOCA buffer representing local buffer (%s)\n", doca_get_error_string(res));
			return;
		}
	}
	return;
}

char *malloc_mem_pool(size_t size)
{
	// align up 4k
	size = ((size + PAGE_SIZE - 1) >> 12) << 12;
	assert((unsigned long)GLOABL_MEM_POOL_FREE + size < (unsigned long)GLOABL_MEM_POOL + DPU_MEM_POOL_SIZE);
	char *ret = atomic_fetch_add((unsigned long *)&GLOABL_MEM_POOL_FREE, size);
	// char *ret = GLOABL_MEM_POOL_FREE;
	// GLOABL_MEM_POOL_FREE = (unsigned long)GLOABL_MEM_POOL_FREE + size;
	return ret;
}

// only for HOST
bool init_dma_client()
{
	doca_error_t res;
	// struct doca_pci_bdf pcie_addr = {.bus = PCI_BUS_ADDR, .device = 00, .function = 0};
	char pcie_addr[PCI_BUF_SIZE] = PCI_BUS_ADDR;
	res = open_local_device(pcie_addr, &state);
	if (res != DOCA_SUCCESS)
	{
		info("open_local_device is failed %s\n", doca_get_error_string(res));
		return false;
	}
	return true;
}

// only for HOST
// this is no memory for export_str, we can give it char pointer
// this function only run in client
bool gen_dma_map_range_export_json(char *src_buffer, size_t length, uint8_t **export_str, size_t *export_str_len)
{
	doca_error_t res;

	res = doca_mmap_set_memrange(state.mmap, src_buffer, length);
	if (res != DOCA_SUCCESS)
	{
		debug("src_buffer %p length 0x%lx\n", src_buffer, length);
		error("Unable to populate memory map: %s\n", doca_get_error_string(res));
		return false;
	}

	struct mmap_range_list *mmap_range = (struct mmap_range_list *)malloc(sizeof(struct mmap_range_list));
	mmap_range->st_addr = (unsigned long)src_buffer;
	mmap_range->ed_addr = length + (unsigned long)src_buffer;
	mmap_range->doca_buf_head = NULL;
	mmap_range->next = NULL;

	struct mmap_range_list *head = mmap_range_head;

	while (head != NULL && head->next != NULL)
	{
		head = head->next;
	}

	if (head == NULL)
	{
		mmap_range_head = mmap_range;
	}
	else
	{
		head->next = mmap_range;
	}
	/* Export DOCA mmap to enable DMA */
	res = doca_mmap_export_dpu(state.mmap, state.dev, (uint8_t **)export_str, export_str_len);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_export: %s\n", doca_get_error_string(res));
		return false;
	}
	return true;
}

bool init_dma_server(uint32_t max_chunks)
{
	// struct doca_pci_bdf pcie_addr = {.bus = PCI_BUS_ADDR, .device = 00, .function = 0};
	char pcie_addr[PCI_BUF_SIZE] = PCI_BUS_ADDR;
	doca_error_t res;
	res = open_local_device(pcie_addr, &state);
	if (res != DOCA_SUCCESS)
	{
		error("open_local_device is failed %s\n", doca_get_error_string(res));
		return false;
	}

	res = create_server_core_objects(&state);
	if (res != DOCA_SUCCESS)
	{
		destroy_server_core_objects(&state);
		return false;
	}

	res = init_server_core_objects(&state, max_chunks);
	if (res != DOCA_SUCCESS)
	{
		cleanup_server_core_objects(&state);
		destroy_server_core_objects(&state);
		return false;
	}
	return true;
}

static void destroy_mmap_range_object(struct mmap_range_list *mmap_range)
{
	struct doca_buf_list *temp_doca_buf = mmap_range->doca_buf_head;
	for (int i = temp_doca_buf->count; i > 0; i--)
	{
		doca_buf_refcount_rm(temp_doca_buf->doca_buf_pointer[i], NULL);
		free(temp_doca_buf);
	}

	doca_error_t res = doca_mmap_destroy(mmap_range->mmap);
	if (res != DOCA_SUCCESS)
		error("Failed to destroy mmap: %s\n", doca_get_error_string(res));
	free(mmap_range);
	return;
}

// only for HOST
// ? sure? print some info in DPU
// TODO !!! this destory_mmap_range_object can't coordinate
static unsigned long handle_addr_old_mmap_range(unsigned long st_addr, size_t length)
{
	struct mmap_range_list *mmap_range = mmap_range_head;
	struct mmap_range_list *temp_mmap_range = mmap_range;
	while (mmap_range != NULL)
	{
		if ((st_addr == mmap_range->st_addr) || (st_addr + (unsigned long)length == mmap_range->ed_addr))
		{
			if (mmap_range == mmap_range_head)
			{
				mmap_range_head = mmap_range->next;
			}
			else
			{
				temp_mmap_range->next = mmap_range->next;
			}
			warning("destory mmap_range st(%#lx) ed(%#lx)\n", mmap_range->st_addr, mmap_range->ed_addr);
			// destroy_mmap_range_object(mmap_range);
			return mmap_range->ed_addr;
		}
		temp_mmap_range = mmap_range;
		mmap_range = mmap_range->next;
	}
	return 0;
}

// only run in DPU
bool gen_memory_range_from_export_json(char *export_json)
{
	struct R_DMA_OBJ *d_o = (struct R_DMA_OBJ *)export_json;
	char *remote_addr = (char *)d_o->addr;
	size_t remote_addr_len = d_o->len;
	debug("remote addr(%#lx) range(%#x) \n", remote_addr, remote_addr_len);
	handle_addr_old_mmap_range((unsigned long)remote_addr, remote_addr_len);
	debug("exit handle_addr_old_mmap_range\n");
	debug("export json %s des_len(%d)\n", export_json, d_o->des_len);
	char export_buf[500];
	encapsulate_export_str_data(export_buf, (uint8_t *)export_json + sizeof(struct R_DMA_OBJ), d_o);
	doca_error_t res = doca_mmap_create_from_export(S_DOCA_MMAP_NAME, export_buf, d_o->des_len, state.dev, &remote_mmap);
	if (res != DOCA_SUCCESS)
	{
		error("doca_mmap_create_from_export failed %s \n", doca_get_error_name(res));
		return false;
	}
	struct mmap_range_list *mmap_range = (struct mmap_range_list *)malloc(sizeof(struct mmap_range_list));

	mmap_range->st_addr = (unsigned long)remote_addr;
	mmap_range->ed_addr = (unsigned long)remote_addr_len + (unsigned long)remote_addr;
	mmap_range->mmap = remote_mmap;
	mmap_range->doca_buf_head = NULL;
	mmap_range->next = NULL;

	struct mmap_range_list *head = mmap_range_head;

	while (head != NULL && head->next != NULL)
	{
		head = head->next;
	}

	if (head == NULL)
	{
		mmap_range_head = mmap_range;
	}
	else
	{
		head->next = mmap_range;
	}

	return true;
}

bool init_share_com_doca_buf(char *remtoe_addr, char *local_addr, size_t lens)
{
	doca_error_t res;

	debug("state.mmap %p local_addr %p lens 0x%lx\n", state.mmap, local_addr, lens);
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, local_addr, lens, &local_share_doca_buf);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to acquire DOCA buffer representing local buffer: %s\n", doca_get_error_string(res));
		return false;
	}

	debug("remote_mmap %p remtoe_addr %p lens 0x%lx\n", remote_mmap, remtoe_addr, lens);
	res = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, remtoe_addr, lens, &remote_share_doca_buf);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to acquire DOCA buffer representing remtoe buffer: %s\n", doca_get_error_string(res));
		return false;
	}
	res = doca_buf_set_data(local_share_doca_buf, local_addr, lens);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to local_addr doca_buf_set_data: %s\n", doca_get_error_string(res));
		return false;
	}
	res = doca_buf_set_data(remote_share_doca_buf, remtoe_addr, lens);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to remtoe_addr doca_buf_set_data: %s\n", doca_get_error_string(res));
		return false;
	}

	return true;
}

static struct doca_job DOCA_JOB_G = {0};
static struct doca_dma_job_memcpy DMA_JOB_G = {0};
static struct doca_dma_job_memcpy DMA_JOB_G1 = {0};
static struct doca_dma_job_memcpy DMA_JOB_G2 = {0};
static struct DMA_WKQ_ST dma_wkq = {0};

static inline int add_dma_wkq(unsigned long x86, unsigned long arm, unsigned int size, unsigned int flag)
{
	int ret_cb_idx = dma_wkq.idx_ed;
	assert(dma_wkq.dma_cb[ret_cb_idx].flag == DMA_CB_F_NONE);
	dma_wkq.dma_cb[ret_cb_idx].x86 = x86;
	dma_wkq.dma_cb[ret_cb_idx].arm = arm;
	dma_wkq.dma_cb[ret_cb_idx].size = size;
	dma_wkq.dma_cb[ret_cb_idx].flag = flag;
	dma_wkq.idx_ed = (ret_cb_idx + 1) % DMA_WORKQ_SIZE;
	// debug5("cb_idx(%#x)\n", ret_cb_idx);
	return ret_cb_idx;
}

#ifndef __x86_64__

#include "mem_map.h"
// return value undefine
static int dma_cb_work(unsigned int cb_idx)
{
	// nothing callback
	if (cb_idx == INVALID_CB_IDX_DATA)
	{
		return 0;
	}
	// debug5("cb_work idx(%#x) \n", cb_idx);
	assert(cb_idx >= 0);
	assert(cb_idx < DMA_WORKQ_SIZE);
	if (dma_wkq.dma_cb[cb_idx].flag == DMA_CB_F_NULL)
	{
		dma_wkq.dma_cb[cb_idx].flag = DMA_CB_F_NONE;
		return 0;
	}
	if (dma_wkq.dma_cb[cb_idx].flag == DMA_CB_F_ADD_CACHE_G)
	{
		// debug6("add x86(%#lx) arm(%#lx) data(%#lx)\n", dma_wkq.dma_cb[cb_idx].x86, dma_wkq.dma_cb[cb_idx].arm, *((unsigned long *)dma_wkq.dma_cb[cb_idx].arm));
		add_cache_mem_g(dma_wkq.dma_cb[cb_idx].x86, dma_wkq.dma_cb[cb_idx].size);
		dma_wkq.dma_cb[cb_idx].flag = DMA_CB_F_NONE;
		return 0;
	}
	dma_wkq.dma_cb[cb_idx].flag = DMA_CB_F_NONE;
	return 0;
}
#else
static int dma_cb_work(unsigned int cb_idx)
{
	return -1;
}
#endif

void init_doca_job()
{
	DOCA_JOB_G.type = DOCA_DMA_JOB_MEMCPY;
	DOCA_JOB_G.flags = DOCA_JOB_FLAGS_NONE;
	DOCA_JOB_G.ctx = state.ctx;
	DMA_JOB_G.base = DOCA_JOB_G;
	DMA_JOB_G.dst_buff = NULL;
	DMA_JOB_G.src_buff = NULL;

	DMA_JOB_G1.base = DOCA_JOB_G;
	DMA_JOB_G1.dst_buff = NULL;
	DMA_JOB_G1.src_buff = NULL;

	DMA_JOB_G2.base = DOCA_JOB_G;
	DMA_JOB_G2.dst_buff = NULL;
	DMA_JOB_G2.src_buff = NULL;
}

// todo !!!

static pthread_spinlock_t dma_mutex = SPINLOCK_INIT_ARM;
static pthread_spinlock_t dma_sub_mutex = SPINLOCK_INIT_ARM;
#define LOCK pthread_spin_lock(&dma_mutex)
#define TRY_LOCK pthread_spin_trylock(&dma_mutex)
#define UNLOCK pthread_spin_unlock(&dma_mutex)
#define LOCK_S pthread_spin_lock(&dma_sub_mutex)
#define TRY_LOCK_S pthread_spin_trylock(&dma_sub_mutex)
#define UNLOCK_S pthread_spin_unlock(&dma_sub_mutex)

struct doca_event event = {0};
volatile static int dma_job_num = 0;
static unsigned long dma_count = 0;

#ifndef DEMO_SERVER
#define DMA_NUM_ATOM_INC                 \
	atomic_fetch_add((&dma_job_num), 1); \
	atomic_fetch_add(&dma_count, 1);
#else
#define DMA_NUM_ATOM_INC atomic_fetch_add(&dma_job_num, 1);
#endif

#define DMA_NUM_ATOM_DEC \
	atomic_fetch_sub(&dma_job_num, 1);

#define DOCA_WKQ_RETRIEVE                                                                        \
	do                                                                                           \
	{                                                                                            \
		LOCK_S;                                                                                  \
		res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE); \
		UNLOCK_S;                                                                                \
	} while (res == DOCA_ERROR_AGAIN);                                                           \
	if (res != DOCA_SUCCESS)                                                                     \
	{                                                                                            \
		error("doca_workq_progress_retrieve failed(%s)\n", doca_get_error_string(res));          \
		sleep(10);                                                                               \
		exit(0);                                                                                 \
	}

// while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) == \
	// 	   DOCA_ERROR_AGAIN)                                                                            \
	// 	;                                                                                               \

#define DMA_WAIT_FINISH                   \
	LOCK;                                 \
	while (dma_job_num > 0)               \
	{                                     \
		DOCA_WKQ_RETRIEVE;                \
		DMA_NUM_ATOM_DEC;                 \
		dma_cb_work(event.user_data.u64); \
	}                                     \
	UNLOCK;

unsigned long get_dma_speed()
{
	return atomic_exchange(&dma_count, 0);
}

bool doca_mem_copy_operate(struct doca_buf *src_doca_buf, struct doca_buf *dst_doca_buf, size_t copy_size, bool is_now)
{
	if (copy_size == 0)
	{
		return true;
	}
	LOCK_S;
	DMA_JOB_G.dst_buff = dst_doca_buf;
	DMA_JOB_G.src_buff = src_doca_buf;
	// ((uint64_t *)src_doca_buf)[3] = copy_size;
	SET_DOCA_BUF_COPY_LEN(src_doca_buf, copy_size);
	SET_DOCA_BUF_COPY_LEN(dst_doca_buf, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	if (is_now == true)
	{
		LOCK;
		while (dma_job_num > 0)
		{
			DOCA_WKQ_RETRIEVE;
			DMA_NUM_ATOM_DEC;
			dma_cb_work(event.user_data.u64);
		}
		UNLOCK;
	}

	return true;
}

struct doca_buf *dist_doca_buf(struct doca_buf_list *remote_dob_buf)
{
	struct doca_buf *ret_dob = remote_dob_buf->doca_buf_pointer[remote_dob_buf->turn];
	remote_dob_buf->turn = (remote_dob_buf->turn + 1) % remote_dob_buf->count;
	return ret_dob;
}

struct doca_buf *get_doca_buf(unsigned long arm_addr, size_t size)
{
	struct doca_buf *ret_dob = arm_global_dob[turn_arm];
	SET_DOCA_BUF_ADDR(ret_dob, arm_addr);
	SET_DOCA_BUF_COPY_LEN(ret_dob, size);
	// ((unsigned long *)ret_dob)[0] = (unsigned long)arm_addr;
	// ((unsigned long *)(ret_dob))[1] = size;
	turn_arm = (turn_arm + 1) % MAX_DOCA_BUF_BUF_COUNT;
	return ret_dob;
}

struct doca_buf *get_doca_buf_dst(unsigned long arm_addr, size_t size)
{
	struct doca_buf *ret_dob = arm_global_dob[turn_arm];
	SET_DOCA_BUF_ADDR(ret_dob, arm_addr);
	SET_DOCA_BUF_COPY_LEN(ret_dob, 0);
	// ((unsigned long *)ret_dob)[0] = (unsigned long)arm_addr;
	// ((unsigned long *)(ret_dob))[1] = size;
	turn_arm = (turn_arm + 1) % MAX_DOCA_BUF_BUF_COUNT;
	return ret_dob;
}

bool doca_mem_copy_from(struct doca_buf_list *remote_dob_buf, unsigned long x86_addr, char *arm_addr, size_t copy_size, int is_now)
{
	if (copy_size == 0)
	{
		return true;
	}
	LOCK_S;
#ifndef __x86_64__
	asm volatile("DSB SY" ::
					 : "memory");
#endif
	struct doca_buf *remote_dob = dist_doca_buf(remote_dob_buf);
	SET_DOCA_BUF_ADDR(remote_dob, x86_addr);
	// ((unsigned long *)(remote_dob))[0] = x86_addr;
	// !!! must set size
	SET_DOCA_BUF_COPY_LEN(remote_dob, copy_size);
	// ((unsigned long *)(remote_dob))[1] = copy_size;
	// ((unsigned long *)arm_global_dob)[0] = (unsigned long)arm_addr;
	// ((unsigned long *)(arm_global_dob))[1] = copy_size;
	DMA_JOB_G.dst_buff = get_doca_buf_dst(arm_addr, copy_size);
	DMA_JOB_G.src_buff = remote_dob;
	// ? this operation is duplicative
	// SET_DOCA_BUF_COPY_LEN(remote_dob,copy_size);
	// ((uint64_t *)remote_dob)[3] = copy_size;
	debug4("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)DMA_JOB_G.dst_buff)[0], ((uint64_t *)DMA_JOB_G.dst_buff)[1], ((uint64_t *)DMA_JOB_G.dst_buff)[2], ((uint64_t *)DMA_JOB_G.dst_buff)[3], ((uint64_t *)remote_dob)[0], ((uint64_t *)remote_dob)[1], ((uint64_t *)remote_dob)[2], ((uint64_t *)remote_dob)[3]);

	doca_error_t res;
	int cb_idx = add_dma_wkq(x86_addr, arm_addr, copy_size, is_now & DMA_CB_F_MUSK);
	DMA_JOB_G.base.user_data.u64 = cb_idx;
	// debug6("x86(%#lx)arm(%#lx)job(%#x)rdob(%#lx)data(%#lx)\n", ((unsigned long *)(remote_dob))[0], arm_addr, dma_job_num, remote_dob, *((unsigned long *)arm_addr));
	BARRIER;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}
	if ((is_now & DMA_SYNC) != 0)
	{
		LOCK;
		while (dma_job_num > 0)
		{
			DOCA_WKQ_RETRIEVE;
			DMA_NUM_ATOM_DEC;
			dma_cb_work(event.user_data.u64);
			if (event.user_data.u64 == cb_idx)
			{
				break;
			}
		}
		UNLOCK;
	}
	return true;
}

bool doca_mem_copy_to(struct doca_buf_list *remote_dob_buf, unsigned long x86_addr, char *arm_addr, size_t copy_size, bool is_now)
{
	if (copy_size == 0)
	{
		return true;
	}
	LOCK_S;
	struct doca_buf *remote_dob = dist_doca_buf(remote_dob_buf);
	SET_DOCA_BUF_ADDR(remote_dob, x86_addr);
	// !!! must set size
	SET_DOCA_BUF_COPY_LEN(remote_dob, 0);
	// ((unsigned long *)(remote_dob))[0] = x86_addr;
	// ((unsigned long *)(remote_dob))[1] = copy_size;
	// ((unsigned long *)arm_global_dob)[0] = arm_addr;
	DMA_JOB_G.dst_buff = remote_dob;
	DMA_JOB_G.src_buff = get_doca_buf((unsigned long)arm_addr, copy_size);
	// todo : Can this operation be omitted?
	// ((uint64_t *)(DMA_JOB_G.src_buff))[3] = copy_size;
	doca_error_t res;
	int cb_idx = add_dma_wkq(x86_addr, arm_addr, copy_size, DMA_CB_F_V1);
	DMA_JOB_G.base.user_data.u64 = cb_idx;
	// debug6("x86(%#lx)arm(%#lx)rdob(%#lx)job(%#x)size(%#x)\n", ((unsigned long *)(remote_dob))[0], arm_addr, remote_dob, dma_job_num, copy_size);
	BARRIER;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	// atomic_fetch_add(&dma_job_num, 1);
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	if (is_now == true)
	{
		LOCK;
		while (dma_job_num > 0)
		{
			DOCA_WKQ_RETRIEVE;
			DMA_NUM_ATOM_DEC;
			dma_cb_work(event.user_data.u64);
			if (event.user_data.u64 == cb_idx)
			{
				break;
			}
		}
		UNLOCK;
	}
	return true;
}

void doca_mem_copy_to_sync(struct doca_buf_list *remote_dob_buf, unsigned long x86_addr, char *arm_addr, size_t copy_size)
{
	if (copy_size == 0)
	{
		return;
	}
	doca_error_t res;

	LOCK;
	LOCK_S;
	while (dma_job_num > 0)
	{
		do
		{
			res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		} while (res == DOCA_ERROR_AGAIN);
		if (res != DOCA_SUCCESS)
		{
			error("doca_workq_progress_retrieve failed(%s)\n", doca_get_error_string(res));
		}
		DMA_NUM_ATOM_DEC;
		dma_cb_work(event.user_data.u64);
	}
	struct doca_buf *remote_dob = dist_doca_buf(remote_dob_buf);
	SET_DOCA_BUF_ADDR(remote_dob, x86_addr);
	// ((unsigned long *)(remote_dob))[0] = x86_addr;
	// !!! must set size
	SET_DOCA_BUF_COPY_LEN(remote_dob, 0);
	// ((unsigned long *)(remote_dob))[1] = copy_size;
	// ((unsigned long *)arm_global_dob)[0] = arm_addr;
	DMA_JOB_G.dst_buff = remote_dob;
	DMA_JOB_G.src_buff = get_doca_buf(arm_addr, copy_size);
	// todo: Is it obligatory to do this operation?
	// ((uint64_t *)(DMA_JOB_G.src_buff))[3] = copy_size;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	// debug6("x86(%#lx)arm(%#lx)size(%#x)\n", x86_addr, arm_addr, copy_size);
	BARRIER;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	// atomic_fetch_add(&dma_job_num, 1);
	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	while (dma_job_num > 0)
	{
		do
		{
			res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		} while (res == DOCA_ERROR_AGAIN);
		if (res != DOCA_SUCCESS)
		{
			error("doca_workq_progress_retrieve failed(%s)\n", doca_get_error_string(res));
		}
		DMA_NUM_ATOM_DEC;
		dma_cb_work(event.user_data.u64);
	}

	UNLOCK_S;
	UNLOCK;
	return;
}

bool sync_from(size_t lens)
{
	doca_error_t res;

	if (dma_job_num < 2)
	{
		LOCK_S;
		DMA_JOB_G1.dst_buff = local_share_doca_buf;
		DMA_JOB_G1.src_buff = remote_share_doca_buf;
		SET_DOCA_BUF_COPY_LEN(remote_share_doca_buf, lens);
		SET_DOCA_BUF_COPY_LEN(local_share_doca_buf, 0);
		DMA_JOB_G1.base.user_data.u64 = INVALID_CB_IDX_DATA;
		// printf("r %#lx l %#lx\n", ((uint64_t *)(remote_share_doca_buf))[2], ((uint64_t *)(local_share_doca_buf))[2]);
		// printf("r %#lx l %#lx\n", ((uint64_t *)(remote_share_doca_buf))[3], ((uint64_t *)(local_share_doca_buf))[3]);
		res = doca_workq_submit(state.workq, &DMA_JOB_G1.base);
		DMA_NUM_ATOM_INC;
		UNLOCK_S;
		if (res != DOCA_SUCCESS)
		{
			error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
		}
	}
	else
	{
		// todo ? why i can't dma wait finish in this section.
		return true;
	}
	DMA_WAIT_FINISH;
	return true;
}

bool sync_to(size_t lens)
{

	DMA_JOB_G1.dst_buff = remote_share_doca_buf;
	DMA_JOB_G1.src_buff = local_share_doca_buf;
	SET_DOCA_BUF_COPY_LEN(local_share_doca_buf, lens);
	SET_DOCA_BUF_COPY_LEN(remote_share_doca_buf, 0);
	doca_error_t res;

	LOCK_S;
	DMA_JOB_G1.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G1.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;
	return true;
}

void unfold_export_str_data(uint8_t *ex_s, size_t export_str_len, struct R_DMA_OBJ *obj)
{
	char buff[300];
#ifdef DEBUG
	// debug ***********************
	printf("before\n");
	for (int i = 0; i < export_str_len; i++)
	{
		printf("%hhx ", ex_s[i]);
	}
	printf("\n");
#endif

	for (int i = 0; i < export_str_len - 8; i++)
	{
		buff[i] = ex_s[i + 8] ^ ((75 + i) & 0xff);
	}
	debug("export %s\n", buff);
	sscanf(buff, EXPORT_STR_FORMAT, &obj->vhca_id, &ex_s[8], &ex_s[9], &ex_s[10], &ex_s[11], &ex_s[12], &ex_s[13], &ex_s[14], &ex_s[15], &ex_s[16], &ex_s[17], &ex_s[18], &ex_s[19], &ex_s[20], &ex_s[21], &ex_s[22], &ex_s[23], &ex_s[24], &ex_s[25], &ex_s[26], &ex_s[27], &ex_s[28], &ex_s[29], &ex_s[30], &ex_s[31], &ex_s[32], &ex_s[33], &ex_s[34], &ex_s[35], &ex_s[36], &ex_s[37], &ex_s[38], &ex_s[39], &obj->addr, &obj->len, &obj->mkey, &obj->page_size);
	obj->des_len = export_str_len;
	debug("vhca_id %d,addr %lld, len %d, mkey %d, pagesize %d\n", obj->vhca_id, obj->addr, obj->len, obj->mkey, obj->page_size);
	return;
}

void encapsulate_export_str_data(uint8_t *out, uint8_t *ex_s, struct R_DMA_OBJ *obj)
{
	memcpy(out, ex_s, 8); // VERSION and Checksum
	sprintf(out + 8, EXPORT_STR_FORMAT, obj->vhca_id, ex_s[8], ex_s[9], ex_s[10], ex_s[11], ex_s[12], ex_s[13], ex_s[14], ex_s[15], ex_s[16], ex_s[17], ex_s[18], ex_s[19], ex_s[20], ex_s[21], ex_s[22], ex_s[23], ex_s[24], ex_s[25], ex_s[26], ex_s[27], ex_s[28], ex_s[29], ex_s[30], ex_s[31], ex_s[32], ex_s[33], ex_s[34], ex_s[35], ex_s[36], ex_s[37], ex_s[38], ex_s[39], obj->addr, obj->len, obj->mkey, obj->page_size);
	for (int i = 0; i < obj->des_len - 8; i++)
	{
		out[i + 8] = out[i + 8] ^ ((75 + i) & 0xff);
	}
#ifdef DEBUG
	// debug ***********************
	printf("after\n");
	for (int i = 0; i < obj->des_len; i++)
	{
		printf("%hhx ", out[i]);
	}
	printf("\n");
#endif
	// ******************************
	return;
}

bool gen_dma_map_range_export_json_client(char *src_buffer, size_t length, uint8_t **export_str, size_t *export_str_len, int permission)
{
	doca_error_t res;
	struct doca_mmap *mmap = NULL;
	client_create_dma_mmap(state.dev, &mmap, permission);

	res = doca_mmap_set_memrange(mmap, src_buffer, length);
	if (res != DOCA_SUCCESS)
	{
		debug("src_buffer %p length 0x%lx\n", src_buffer, length);
		error("Unable to populate memory map: %s\n", doca_get_error_string(res));
		return false;
	}

	res = doca_mmap_start(mmap);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to start memory map: %s\n", doca_get_error_string(res));
		return res;
	}

	struct mmap_range_list *mmap_range = (struct mmap_range_list *)malloc(sizeof(struct mmap_range_list));
	mmap_range->st_addr = (unsigned long)src_buffer;
	mmap_range->ed_addr = length + (unsigned long)src_buffer;
	mmap_range->mmap = mmap;
	mmap_range->doca_buf_head = NULL;
	mmap_range->next = NULL;

	struct mmap_range_list *head = mmap_range_head;

	while (head != NULL && head->next != NULL)
	{
		head = head->next;
	}

	if (head == NULL)
	{
		mmap_range_head = mmap_range;
	}
	else
	{
		head->next = mmap_range;
	}

	/* Export DOCA mmap to enable DMA */
	res = doca_mmap_export_dpu(mmap, state.dev, (uint8_t **)export_str, export_str_len);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to doca_mmap_export: %s\n", doca_get_error_string(res));
		return false;
	}
	return true;
}

static bool addr_is_in_mmaps(unsigned long addr)
{
	struct mmap_range_list *mmap_range = mmap_range_head;
	while (mmap_range != NULL)
	{
		if (addr >= mmap_range->st_addr && addr < mmap_range->ed_addr)
		{
			return true;
		}

		mmap_range = mmap_range->next;
	}
	return false;
}

struct mmap_range_list *get_remote_mmap_range_by_addr(unsigned long addr)
{
	struct mmap_range_list *mmap_range = mmap_range_head;
	while (mmap_range != NULL)
	{
		if (addr >= mmap_range->st_addr && addr < mmap_range->ed_addr)
		{
			return mmap_range;
		}
		mmap_range = mmap_range->next;
	}
	return NULL;
}

// handle memory_client only for host
void handle_memory_client(char *addr)
{
	bool res = addr_is_in_mmaps((unsigned long)addr);
	if (res)
	{
		return;
	}
	char perms[5];
	debug("find perms\n");
	info("mmap new addr(0x%lx)\n", addr);
	size_t length = get_addr_range_info(&addr, perms);
	if (length == 0)
	{
		info("get addr range info error addr(%p)\n", addr);
		return;
	}
	// !!! patch those code

	handle_addr_old_mmap_range((unsigned long)addr, length);

	char *export;
	size_t export_size;
	int perm = 0;
	debug("find perms %s\n", perms);
	char *temp = strchr(perms, 'r');
	if (temp != NULL && temp[0] == 'r')
	{
		perm |= PER_READ;
	}
	temp = strchr(perms, 'w');
	if (temp != NULL && temp[0] == 'w')
	{
		perm |= PER_WRITE;
	}
	res = gen_dma_map_range_export_json_client(addr, length, &export, &export_size, perm);
	if (res == false)
	{
		info("gen_dma_map_range_export_json_client failed addr(%p), length (0x%lx)\n", addr, length);
		return;
	}
	// debug *************************

	// 	t = [s[i+8]^((75+i)&0xff) for i in range(len(s)-8)]
	// >>> "".join([chr(i) for i in t])
	// '{"vhca_id":0,"access_key":[0,0,146,235,85,13,40,242,4,136,225,216,134,70,47,196,249,250,222,38,171,116,221,83,78,208,100,14,111,117,184,222],"mchunk":{"addr":140737215873024,"len":134340608,"mkey":2105922,"page_size":4096}}\x00'

	// sscanf(buff,"{\"vhca_id\":%*d,\"access_key\":[%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d,%*d],\"mchunk\":{\"addr\":%ld,\"len\":%d,\"mkey\":%*d,\"page_size\":%*d}}",&addr_2,&len_2);

	// *******************************
	info("new addr range mmap addr(%p), length (0x%lx)\n", addr, length);
	// TODO !!! add the mutex lock in order for multi-threads
	// TODO !!! Should use D_CLIENT_FIN or D_TO_SERVER
	debug("export %s export_size %d\n", export, export_size);
	while (sync_ctrl_cmd->direct == D_TO_CLIENT)
		;
	struct R_DMA_OBJ dma_obj;
	unfold_export_str_data(export, export_size, &dma_obj);
	memcpy(sync_ctrl_cmd->data, (char *)&dma_obj, sizeof(struct R_DMA_OBJ));
	memcpy(sync_ctrl_cmd->data + sizeof(struct R_DMA_OBJ), export, EXPORT_MMAP_DATA_TRANS_LEN);

	// memcpy(sync_ctrl_cmd->data, export, export_size + 1);
	sync_ctrl_cmd->flag = F_SET_REMOTE_MMAP_RANGE;
	sync_ctrl_cmd->direct = D_TO_SERVER;
	debug("sync ip %p\n", sync_ctrl_cmd);
	while (sync_ctrl_cmd->direct != D_TO_CLIENT)
		;
	// !!! must be to reply the client

	sync_ctrl_cmd->direct = D_CLIENT_FIN;

	return;
}

// handle memory_client only for host
void handle_memory_client2(char *addr, struct ofd_contrl_msg *ofd_msg)
{
	bool res = addr_is_in_mmaps((unsigned long)addr);
	if (res)
	{
		return;
	}
	char perms[5];
	debug("find perms\n");
	info("mmap new addr(0x%lx)\n", addr);
	size_t length = get_addr_range_info(&addr, perms);
	if (length == 0)
	{
		error("get addr range info error addr(%p)\n", addr);
		exit(0);
	}

	unsigned long add_addr = handle_addr_old_mmap_range((unsigned long)addr, length);
	if (add_addr != 0)
	{
		length = length - (add_addr - (unsigned long)addr);
		addr = (char *)add_addr;
	}

	char *export;
	size_t export_size;
	int perm = 0;
	debug("find perms %s\n", perms);
	char *temp = strchr(perms, 'r');
	if (temp != NULL && temp[0] == 'r')
	{
		perm |= PER_READ;
	}
	temp = strchr(perms, 'w');
	if (temp != NULL && temp[0] == 'w')
	{
		perm |= PER_WRITE;
	}
	res = gen_dma_map_range_export_json_client(addr, length, &export, &export_size, perm);
	if (res == false)
	{
		info("gen_dma_map_range_export_json_client failed addr(%p), length (0x%lx)\n", addr, length);
		return;
	}
	info("new addr range mmap addr(%p), length (0x%lx)\n", addr, length);
	debug2("export %s export_size %d\n", export, export_size);

	struct R_DMA_OBJ dma_obj;
	unfold_export_str_data(export, export_size, &dma_obj);

	memcpy(ofd_msg->data, (char *)&dma_obj, sizeof(struct R_DMA_OBJ));
	memcpy(ofd_msg->data + sizeof(struct R_DMA_OBJ), export, EXPORT_MMAP_DATA_TRANS_LEN);
	// memcpy(ofd_msg->data, export, export_size + 1);
	ofd_msg->flag = F_SET_REMOTE_MMAP_RANGE;
	ofd_msg->direct = D_TO_SERVER;
	// while (ofd_msg->direct != D_TO_CLIENT)
	// 	;
	// // !!! must be to reply the client

	// ofd_msg->direct = D_CLIENT_FIN;

	return;
}

// only for dpu
void *get_doca_buf_pointer_in_dpu(unsigned long addr, unsigned long size)
{
	struct doca_buf *local_doca_buf = NULL;
	doca_error_t res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, addr, size, &local_doca_buf);
	if (res != DOCA_SUCCESS)
	{
		error("Unable to acquire DOCA buffer representing local buffer: %s\n", doca_get_error_string(res));
		return NULL;
	}
	return (void *)local_doca_buf;
}

// only for remote address
// this function will be not used other except mem_map
struct doca_buf_list *get_r_doca_buf_list(unsigned long remote_addr, size_t count)
{
	struct mmap_range_list *remtoe_mmap_range = get_remote_mmap_range_by_addr(remote_addr);
	if (remtoe_mmap_range == NULL)
	{
		error("remote mmap range is not ready error addr(%p)\n", remote_addr);
		return NULL;
	}

	struct doca_buf_list *doca_inve = remtoe_mmap_range->doca_buf_head;

	struct doca_buf *remote_doca_buf;
	if (doca_inve == NULL)
	{
		doca_error_t res = doca_buf_inventory_buf_by_addr(state.buf_inv, remtoe_mmap_range->mmap, remote_addr, count, &remote_doca_buf);
		if (res != DOCA_SUCCESS)
		{
			error("Unable to acquire DOCA buffer representing remtoe buffer: %s\n", doca_get_error_string(res));
			return false;
		}
		doca_inve = (struct doca_buf_list *)malloc(sizeof(struct doca_buf_list));
		doca_inve->count = 1;
		doca_inve->turn = 0;
		doca_inve->doca_buf_pointer[0] = remote_doca_buf;
		remtoe_mmap_range->doca_buf_head = doca_inve;
	}
	else
	{
		//!!! patch add more doca_buf
		if (doca_inve->count < MAX_DOCA_BUF_BUF_COUNT)
		{
			doca_error_t res = doca_buf_inventory_buf_by_addr(state.buf_inv, remtoe_mmap_range->mmap, remote_addr, count, &remote_doca_buf);
			if (res != DOCA_SUCCESS)
			{
				error("Unable to acquire DOCA buffer representing remtoe buffer: %s\n", doca_get_error_string(res));
				exit(1);
			}
			doca_inve->doca_buf_pointer[doca_inve->count] = remote_doca_buf;
			doca_inve->count = doca_inve->count + 1;
		}
	}
	return doca_inve;
}

struct doca_buf *l_read_buf_dob = NULL;
struct doca_buf *l_write_buf_dob = NULL;
struct doca_buf *l_ring_ed_inv_dob = NULL;
struct doca_buf *l_ring_st_inv_dob = NULL;
struct doca_buf *l_ep_en_ring_dob = NULL;

struct doca_buf *r_read_buf_dob = NULL;
struct doca_buf *r_write_buf_dob = NULL;
struct doca_buf *r_ring_ed_inv_dob = NULL;
struct doca_buf *r_ring_st_inv_dob = NULL;
struct doca_buf *r_ep_en_ring_dob = NULL;

// todo !! **
// !!! MAX_CPUS
char (*d_read_buf_ring)[READ_BUF_SIZE] = NULL;
char *d_write_buf_ring = NULL;
struct RING_INFO_ED *d_ring_ed_inv = NULL;
struct RING_INFO_ST *d_ring_st_inv = NULL;
struct EP_EVENT_ARM *d_ep_en_ring = NULL;

char (*off_thread_write_buf_arr)[W_BUF_S_ONCE] = NULL;

unsigned long r_read_ring_addr = 0;
unsigned long r_write_ring_addr = 0;
unsigned long r_ring_ed_inv_addr = 0; // don't use
unsigned long r_ring_st_inv_addr = 0; // don't use
unsigned long r_ep_en_ring_addr = 0;

void setup_ring_info_init(unsigned long read_ring_addr, unsigned long ring_ed_inv_addr, unsigned long ring_st_inv_addr, unsigned long ep_en_ring_addr, unsigned long write_ring_addr)
{
	r_read_ring_addr = read_ring_addr;
	r_write_ring_addr = write_ring_addr;
	r_ring_ed_inv_addr = ring_ed_inv_addr;
	r_ring_st_inv_addr = ring_st_inv_addr;
	r_ep_en_ring_addr = ep_en_ring_addr;

	info("read_ring_addr(%p), ring_ed_inv_addr(%p), ring_st_inv_addr(%p), ep_en_ring_addr(%p)\n", read_ring_addr, ring_ed_inv_addr, ring_st_inv_addr, ep_en_ring_addr);
	// TODO macro rewrite
	d_read_buf_ring = (char *)malloc_mem_pool(READ_BUF_SIZE * MTCP_THREAD_NUM);
	// for (int j = 0; j < MTCP_THREAD_NUM - 1; j++)
	// {
	// 	d_read_buf_ring[j + 1] = d_read_buf_ring[j] + READ_BUF_SIZE;
	// }
	d_write_buf_ring = (char *)malloc_mem_pool(WRITE_BUF_SIZE);
	memset(d_read_buf_ring, 0, READ_BUF_SIZE * MTCP_THREAD_NUM);
	d_ring_ed_inv = malloc_mem_pool(sizeof(struct RING_INFO_ED));
	// initial
	d_ring_ed_inv->ed_ep_en_off = 0;
	d_ring_ed_inv->ed_read_buf_off[0] = 0;
	d_ring_ed_inv->st_write_buf_off = 0;

	d_ring_st_inv = malloc_mem_pool(sizeof(struct RING_INFO_ST));
	memset(d_ring_st_inv, 0, sizeof(struct RING_INFO_ST));
	d_ep_en_ring = malloc_mem_pool(sizeof(struct EP_EVENT_ARM) * MAX_EPOLL_EVENT_NUM);
	memset(d_ep_en_ring, 0, sizeof(struct EP_EVENT_ARM) * MAX_EPOLL_EVENT_NUM);

	off_thread_write_buf_arr = malloc_mem_pool(W_BUF_S_ONCE * MTCP_THREAD_NUM);

	info("read_ring_addr(%p), ring_ed_inv(%p), ring_st_inv(%p), ep_en_ring(%p)\n", d_read_buf_ring, d_ring_ed_inv, d_ring_st_inv, d_ep_en_ring);
	doca_error_t res;
	DOCA_BUF_APPLY(d_read_buf_ring, READ_BUF_SIZE * MTCP_THREAD_NUM, l_read_buf_dob);
	DOCA_BUF_APPLY(d_write_buf_ring, WRITE_BUF_SIZE, l_write_buf_dob);
	DOCA_BUF_APPLY(d_ring_ed_inv, sizeof(struct RING_INFO_ED), l_ring_ed_inv_dob);
	DOCA_BUF_APPLY(d_ring_st_inv, sizeof(struct RING_INFO_ST), l_ring_st_inv_dob);
	DOCA_BUF_APPLY(d_ep_en_ring, sizeof(struct EP_EVENT_ARM) * MAX_EPOLL_EVENT_NUM, l_ep_en_ring_dob);

	struct mmap_range_list *remtoe_mmap_range;
	DOCA_BUF_APPLY_FOR_REMOTE(read_ring_addr, READ_BUF_SIZE * MTCP_THREAD_NUM, r_read_buf_dob);
	DOCA_BUF_APPLY_FOR_REMOTE(write_ring_addr, WRITE_BUF_SIZE, r_write_buf_dob);
	DOCA_BUF_APPLY_FOR_REMOTE(ring_ed_inv_addr, sizeof(struct RING_INFO_ED), r_ring_ed_inv_dob);
	DOCA_BUF_APPLY_FOR_REMOTE(ring_st_inv_addr, sizeof(struct RING_INFO_ST), r_ring_st_inv_dob);
	DOCA_BUF_APPLY_FOR_REMOTE(ep_en_ring_addr, sizeof(struct EP_EVENT_ARM) * MAX_EPOLL_EVENT_NUM, r_ep_en_ring_dob);
	debug("exit setup_ring_info_init is ok\n");
	return;
}

bool sync_read_buf_to(int qid, unsigned int offset, unsigned int size)
{
	// modify the address
	SET_DOCA_BUF_ADDR(l_read_buf_dob, (unsigned long)(d_read_buf_ring[qid]) + offset);
	SET_DOCA_BUF_ADDR(r_read_buf_dob, r_read_ring_addr + qid * READ_BUF_SIZE + offset);
	// ((unsigned long *)r_read_buf_dob)[0] = r_read_ring_addr + offset;

	LOCK_S;
	DMA_JOB_G.dst_buff = r_read_buf_dob;
	DMA_JOB_G.src_buff = l_read_buf_dob;
	SET_DOCA_BUF_COPY_LEN(l_read_buf_dob, size);
	SET_DOCA_BUF_COPY_LEN(r_read_buf_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}
	return true;
}

bool sync_write_buf_from(unsigned int offset, unsigned int size, bool is_now)
{
	// modify the address
	SET_DOCA_BUF_ADDR(l_write_buf_dob, (unsigned long)d_write_buf_ring + offset);
	// ((unsigned long *)l_write_buf_dob)[2] = (unsigned long)d_write_buf_ring + offset;
	SET_DOCA_BUF_ADDR(r_write_buf_dob, r_write_ring_addr + offset);
	// ((unsigned long *)r_write_buf_dob)[2] = r_write_ring_addr + offset;
	LOCK_S;
	DMA_JOB_G.dst_buff = l_write_buf_dob;
	DMA_JOB_G.src_buff = r_write_buf_dob;
	SET_DOCA_BUF_COPY_LEN(r_write_buf_dob, size);
	SET_DOCA_BUF_COPY_LEN(l_write_buf_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	// debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_write_buf_dob)[0], ((uint64_t *)l_write_buf_dob)[1], ((uint64_t *)l_write_buf_dob)[2], ((uint64_t *)l_write_buf_dob)[3], ((uint64_t *)r_write_buf_dob)[0], ((uint64_t *)r_write_buf_dob)[1], ((uint64_t *)r_write_buf_dob)[2], ((uint64_t *)r_write_buf_dob)[3]);
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;
	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
		exit(0);
	}

	if (is_now)
	{
		DMA_WAIT_FINISH;
	}

	return true;
}

void sync_write_buf_from_now(unsigned int size)
{
	LOCK_S;
	DMA_JOB_G.dst_buff = l_write_buf_dob;
	DMA_JOB_G.src_buff = r_write_buf_dob;
	SET_DOCA_BUF_COPY_LEN(r_write_buf_dob, size);
	SET_DOCA_BUF_COPY_LEN(l_write_buf_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	// debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_write_buf_dob)[0], ((uint64_t *)l_write_buf_dob)[1], ((uint64_t *)l_write_buf_dob)[2], ((uint64_t *)l_write_buf_dob)[3], ((uint64_t *)r_write_buf_dob)[0], ((uint64_t *)r_write_buf_dob)[1], ((uint64_t *)r_write_buf_dob)[2], ((uint64_t *)r_write_buf_dob)[3]);
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;
	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;
	return;
}

bool sync_write_buf_to(unsigned int offset, unsigned int size, bool is_now)
{
	// modify the address
	SET_DOCA_BUF_ADDR(l_write_buf_dob, (unsigned long)d_write_buf_ring + offset);
	// ((unsigned long *)l_write_buf_dob)[0] = (unsigned long)d_write_buf_ring + offset;
	SET_DOCA_BUF_ADDR(r_write_buf_dob, r_write_ring_addr + offset);
	// ((unsigned long *)r_write_buf_dob)[0] = r_write_ring_addr + offset;
	LOCK_S;
	DMA_JOB_G.dst_buff = r_write_buf_dob;
	DMA_JOB_G.src_buff = l_write_buf_dob;
	SET_DOCA_BUF_COPY_LEN(l_write_buf_dob, size);
	SET_DOCA_BUF_COPY_LEN(r_write_buf_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	// debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_write_buf_dob)[0], ((uint64_t *)l_write_buf_dob)[1], ((uint64_t *)l_write_buf_dob)[2], ((uint64_t *)l_write_buf_dob)[3], ((uint64_t *)r_write_buf_dob)[0], ((uint64_t *)r_write_buf_dob)[1], ((uint64_t *)r_write_buf_dob)[2], ((uint64_t *)r_write_buf_dob)[3]);
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}
	if (is_now)
	{
		DMA_WAIT_FINISH;
	}
	return true;
}

bool sync_ep_en_ring_to(unsigned int offset, unsigned int count)
{
	SET_DOCA_BUF_ADDR(l_ep_en_ring_dob, (unsigned long)d_ep_en_ring + offset * sizeof(struct EP_EVENT_ARM));
	// ((unsigned long *)l_ep_en_ring_dob)[0] = (unsigned long)d_ep_en_ring + offset * sizeof(struct EP_EVENT_ARM);
	SET_DOCA_BUF_ADDR(r_ep_en_ring_dob, r_ep_en_ring_addr + offset * sizeof(struct EP_EVENT_ARM));
	// ((unsigned long *)r_ep_en_ring_dob)[0] = r_ep_en_ring_addr + offset * sizeof(struct EP_EVENT_ARM);
	LOCK_S;
	DMA_JOB_G.dst_buff = r_ep_en_ring_dob;
	DMA_JOB_G.src_buff = l_ep_en_ring_dob;
	SET_DOCA_BUF_COPY_LEN(l_ep_en_ring_dob, count * sizeof(struct EP_EVENT_ARM));
	SET_DOCA_BUF_COPY_LEN(r_ep_en_ring_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	return true;
}

void barrier_finish_all_doca()
{
	doca_error_t res;
	LOCK;
	while (dma_job_num > 0)
	{
		DOCA_WKQ_RETRIEVE;
		DMA_NUM_ATOM_DEC;
		dma_cb_work(event.user_data.u64);
	}
	UNLOCK;
	return;
}

bool sync_ring_ed_inv_to(int count, bool sync_flag)
{

	doca_error_t res;
	barrier_finish_all_doca();
	LOCK_S;
	DMA_JOB_G.dst_buff = r_ring_ed_inv_dob;
	DMA_JOB_G.src_buff = l_ring_ed_inv_dob;
	SET_DOCA_BUF_COPY_LEN(l_ring_ed_inv_dob, RING_ED_HEADER_SIZE + count * sizeof(struct FD_READ_ED));
	SET_DOCA_BUF_COPY_LEN(r_ring_ed_inv_dob, 0);
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	if (sync_flag == true)
	{
		DMA_WAIT_FINISH;
	}

	return true;
}

bool sync_ring_st_inv_from(int count, bool sync_flag)
{
	LOCK_S;
	DMA_JOB_G.dst_buff = l_ring_st_inv_dob;
	DMA_JOB_G.src_buff = r_ring_st_inv_dob;
	SET_DOCA_BUF_COPY_LEN(r_ring_st_inv_dob, RING_ST_HEADER_SIZE + count * sizeof(struct FD_READ_ST));
	SET_DOCA_BUF_COPY_LEN(l_ring_st_inv_dob, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	if (sync_flag)
	{
		DMA_WAIT_FINISH;
	}
	return true;
}

struct doca_buf *l_ofd_msg_dob = NULL;
struct doca_buf *r_ofd_msg_dob = NULL;
struct doca_buf *l_ofd_msg_dob2 = NULL;
struct doca_buf *r_ofd_msg_dob2 = NULL;
struct ofd_contrl_msg *d_ofd_code_addr = NULL;
struct ofd_contrl_msg *d_ofd_code_addr2 = NULL;
void init_ofd_code_msg(unsigned long r_ofd_code_msg_addr)
{
	char *l_ofd_msg_buf_addr = malloc_mem_pool(OFD_MSG_BUF_SIZE_TOTAL);
	d_ofd_code_addr = (struct ofd_contrl_msg *)l_ofd_msg_buf_addr;
	d_ofd_code_addr2 = (struct ofd_contrl_msg *)(l_ofd_msg_buf_addr + OFD_CODE_MSG_BUF_SIZE);
	debug2("ofd_msg addr dpu (%#lx) host (%#lx)\n", d_ofd_code_addr2, r_ofd_code_msg_addr);
	doca_error_t res;
	DOCA_BUF_APPLY(l_ofd_msg_buf_addr, OFD_CODE_MSG_BUF_SIZE, l_ofd_msg_dob);
	DOCA_BUF_APPLY(l_ofd_msg_buf_addr + OFD_CODE_MSG_BUF_SIZE, OFD_CODE_MSG_BUF_SIZE2, l_ofd_msg_dob2);

	struct mmap_range_list *remtoe_mmap_range;
	DOCA_BUF_APPLY_FOR_REMOTE(r_ofd_code_msg_addr, OFD_CODE_MSG_BUF_SIZE, r_ofd_msg_dob);
	DOCA_BUF_APPLY_FOR_REMOTE(r_ofd_code_msg_addr + OFD_CODE_MSG_BUF_SIZE, OFD_CODE_MSG_BUF_SIZE2, r_ofd_msg_dob2);
	DOCA_BUF_SET_INFO(r_ofd_msg_dob2, r_ofd_code_msg_addr + OFD_CODE_MSG_BUF_SIZE, OFD_CODE_MSG_BUF_SIZE2);
	DOCA_BUF_SET_INFO(l_ofd_msg_dob2, l_ofd_msg_buf_addr + OFD_CODE_MSG_BUF_SIZE, OFD_CODE_MSG_BUF_SIZE2);
	debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_ofd_msg_dob2)[0], ((uint64_t *)l_ofd_msg_dob2)[1], ((uint64_t *)l_ofd_msg_dob2)[2], ((uint64_t *)l_ofd_msg_dob2)[3], ((uint64_t *)r_ofd_msg_dob2)[0], ((uint64_t *)r_ofd_msg_dob2)[1], ((uint64_t *)r_ofd_msg_dob2)[2], ((uint64_t *)r_ofd_msg_dob2)[3]);
}

//  add mutex if multi threads
void sync_ofd_msg_from(size_t lens)
{
	doca_error_t res;
	LOCK_S;
	DMA_JOB_G.dst_buff = l_ofd_msg_dob;
	DMA_JOB_G.src_buff = r_ofd_msg_dob;
	SET_DOCA_BUF_COPY_LEN(r_ofd_msg_dob, lens);
	SET_DOCA_BUF_COPY_LEN(l_ofd_msg_dob, 0);
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;
	return;
}

void sync_ofd_msg_to(size_t lens)
{
	LOCK_S;
	DMA_JOB_G.dst_buff = r_ofd_msg_dob;
	DMA_JOB_G.src_buff = l_ofd_msg_dob;
	SET_DOCA_BUF_COPY_LEN(l_ofd_msg_dob, lens);
	SET_DOCA_BUF_COPY_LEN(r_ofd_msg_dob, 0);
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	doca_error_t res;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;

	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;

	return;
}

//  add mutex if multi threads
void sync_ofd_msg_from2(size_t lens)
{
	doca_error_t res;
	LOCK_S;
	DMA_JOB_G.dst_buff = l_ofd_msg_dob2;
	DMA_JOB_G.src_buff = r_ofd_msg_dob2;
	SET_DOCA_BUF_COPY_LEN(r_ofd_msg_dob2, OFD_CODE_MSG_BUF_SIZE2);
	SET_DOCA_BUF_COPY_LEN(l_ofd_msg_dob2, 0);
	DMA_JOB_G2.base.user_data.u64 = INVALID_CB_IDX_DATA;
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	// debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_ofd_msg_dob2)[0], ((uint64_t *)l_ofd_msg_dob2)[1], ((uint64_t *)l_ofd_msg_dob2)[2], ((uint64_t *)l_ofd_msg_dob2)[3], ((uint64_t *)r_ofd_msg_dob2)[0], ((uint64_t *)r_ofd_msg_dob2)[1], ((uint64_t *)r_ofd_msg_dob2)[2], ((uint64_t *)r_ofd_msg_dob2)[3]);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;
	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;
	return;
}

//  add mutex if multi threads
void sync_ofd_msg_to2(size_t lens)
{
	LOCK_S;
	DMA_JOB_G.dst_buff = r_ofd_msg_dob2;
	DMA_JOB_G.src_buff = l_ofd_msg_dob2;
	SET_DOCA_BUF_COPY_LEN(l_ofd_msg_dob2, OFD_CODE_MSG_BUF_SIZE2);
	SET_DOCA_BUF_COPY_LEN(r_ofd_msg_dob2, 0);
	doca_error_t res;
	DMA_JOB_G.base.user_data.u64 = INVALID_CB_IDX_DATA;
	debug2("dpu(%#lx) (%#lx) (%#lx) (%#lx) host (%#lx) (%#lx) (%#lx) (%#lx) \n", ((uint64_t *)l_ofd_msg_dob2)[0], ((uint64_t *)l_ofd_msg_dob2)[1], ((uint64_t *)l_ofd_msg_dob2)[2], ((uint64_t *)l_ofd_msg_dob2)[3], ((uint64_t *)r_ofd_msg_dob2)[0], ((uint64_t *)r_ofd_msg_dob2)[1], ((uint64_t *)r_ofd_msg_dob2)[2], ((uint64_t *)r_ofd_msg_dob2)[3]);
	res = doca_workq_submit(state.workq, &DMA_JOB_G.base);
	DMA_NUM_ATOM_INC;
	UNLOCK_S;
	if (res != DOCA_SUCCESS)
	{
		error("Failed to submit DMA job: %s\n", doca_get_error_string(res));
	}

	DMA_WAIT_FINISH;

	return;
}
