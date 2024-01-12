#include "dma_func.h"
#include "mem_map.h"
#include <stdbool.h>
#include "ofd_info.h"
#include "utils.h"
#include <assert.h>
#include "config.h"
#include <string.h>
#include <stdatomic.h>
#include "dma_callback.h"

#define MMU_PAGE_SIZE 0x151
#define MEM_CACHE_MAX_NUM 500
#define STACK_SYNC_SIZE 0x200

#define EVERY_CACHE_SIZE 4096
#define CACHE_SIZE_BIT_NUM 12
#define CACHE_SIZE_MUSK 0xfff

#define CACHE_SIZE_WRITE_BIT 4
#define CACHE_SIZE_WRITE_MUST 0xf
#define EVERY_CACHE_WRITE_SIZE 8

#define GLOBAL_CACHE_NUM 1000

#define ADDR_MAP_UNIT_SIZE 0x1000
#define ADDR_MAP_UNIT_BIT 12

#define HASH_TABLE_SIZE 113
#define HASH_GET_INDEX(x86_addr) (((((x86_addr >> ADDR_MAP_UNIT_BIT) & 0xffff))) % HASH_TABLE_SIZE)

static struct ADDR_MAP *map_list[HASH_TABLE_SIZE] = {0};

static void *free_mmu = NULL;
pthread_spinlock_t mutex_ofd_msg = SPINLOCK_INIT_ARM;
static pthread_spinlock_t mutex_map_doca = SPINLOCK_INIT_ARM;
static int in_write_threads = 0;
int start_write_threads = 0;
#define MAP_DOCA_LOCK pthread_spin_lock(&mutex_map_doca);
#define MAP_DOCA_UNLOCK pthread_spin_unlock(&mutex_map_doca);

struct MEM_CACHE
{
    unsigned long fs;
    unsigned long sync_addr;
    unsigned long count;
    unsigned long x86_addr[MEM_CACHE_MAX_NUM];
    unsigned int size[MEM_CACHE_MAX_NUM];
};

struct GLOABL_CACHE
{
    unsigned int count;
    unsigned int bar_addr_count;
    unsigned long bar_sync_addr[MAX_DPU_IO_THREADS_NUM];
    unsigned long x86_addr[GLOBAL_CACHE_NUM];
    unsigned short size[GLOBAL_CACHE_NUM];
    unsigned short attr[GLOBAL_CACHE_NUM];
};

#define CACHE_WRITE_NUM 0x200

struct CACHE_WRITE
{
    unsigned long x86_addr[CACHE_WRITE_NUM];
    unsigned long addr_map[CACHE_WRITE_NUM];
    unsigned long data[CACHE_WRITE_NUM];
    unsigned char attr[CACHE_WRITE_NUM];
    unsigned short count;
};

struct H_IO_THREAD_INFO
{
    unsigned int count;
    unsigned long h_fs[MAX_DPU_IO_THREADS_NUM];
    struct ADDR_MAP *stack_ad_map[MAX_DPU_IO_THREADS_NUM];
};

static struct FUN_TO_DO zfree_func = {0};
// static struct MEM_CACHE mem_cache[MAX_DPU_IO_THREADS_NUM] = {0};
static struct GLOABL_CACHE mem_g_cache = {0};
static struct CACHE_WRITE mem_w_cache = {0};
static struct H_IO_THREAD_INFO host_threads = {0};

#define MISS 0
#define HIT 1
#define SYNC_F 2
#define FETCH_TEST_NUM 10

#define HIT_WRITE 0x80
#define MISS_WRITE 0x40
#define CACHE_SIZE_WRITE 0x20

static void sync_mem_from(struct ADDR_MAP *ad_map, unsigned long arm_addr, int size);

static int access_cache_mem_g(unsigned long x86_addr, unsigned int size)
{
    for (int j = mem_g_cache.count - 1; j >= 0; j--)
    {
        if (x86_addr >= mem_g_cache.x86_addr[j] && ((signed long)x86_addr - mem_g_cache.x86_addr[j] <= (signed long)mem_g_cache.size[j] - size))
        {
            return HIT;
        }
    }
    if (mem_g_cache.count == 0)
    {
        for (int i = mem_g_cache.bar_addr_count - 1; i >= 0; i--)
        {
            if (mem_g_cache.bar_sync_addr[i] == x86_addr)
            {
                return SYNC_F;
            }
        }
        debug4("miss count(%d) addr (%#lx) sync0(%#lx)sync1(%#lx)\n", mem_g_cache.bar_addr_count, x86_addr, mem_g_cache.bar_sync_addr[0], mem_g_cache.bar_sync_addr[1]);
        return MISS;
    }
    return MISS;
}

// only for write operation
static int access_cache_mem_g2(unsigned long x86_addr, unsigned int size)
{
    for (int j = mem_g_cache.count - 1; j >= 0; j--)
    {
        if (x86_addr >= mem_g_cache.x86_addr[j] && ((signed long)x86_addr - mem_g_cache.x86_addr[j] <= (signed long)mem_g_cache.size[j] - size))
        {
            return mem_g_cache.size[j];
        }
    }
    return MISS;
}

static void add_bar_cache_mem(unsigned long x86_addr)
{
    // debug4("bar addr(%#lx)\n", x86_addr);
    if (mem_g_cache.bar_addr_count == ofd_threads_count)
    {
        return;
    }
    for (int i = mem_g_cache.bar_addr_count - 1; i >= 0; i--)
    {
        if (mem_g_cache.bar_sync_addr[i] == x86_addr)
        {
            return;
        }
    }
    int idx = atomic_fetch_add(&(mem_g_cache.bar_addr_count), 1);
    mem_g_cache.bar_sync_addr[idx] = x86_addr;
}

// TODO to be optimization. because there is no miss write address
static void update_write_cache_mem(unsigned long x86_addr, unsigned int size)
{
    for (int j = mem_w_cache.count - 1; j >= 0; j--)
    {
        if ((mem_w_cache.attr[j] & MISS_WRITE) != MISS_WRITE)
        {
            continue;
        }
        else if (((mem_w_cache.x86_addr[j] >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM) == x86_addr)
        {
            struct ADDR_MAP *ad_map = (struct ADDR_MAP *)mem_w_cache.addr_map[j];
            unsigned long arm_addr = (x86_addr - ad_map->x86_addr) + ad_map->arm_addr;
            unsigned long data = mem_w_cache.data[j];
            switch (mem_w_cache.attr[j] & 0xf)
            {
            case QUADRA_WORD:
                *((unsigned long *)arm_addr) = data;
                break;
            case DOUBLE_WORD:
                *((unsigned int *)arm_addr) = data & 0xffffffff;
                break;
            case HALF_WORD:
                *((unsigned char *)arm_addr) = data & 0xff;
                break;
            default:
                error("error FLAG(%d)\n", mem_w_cache.attr[j] & 0xf);
                break;
            }
            mem_w_cache.attr[j] = HIT_WRITE;
        }
    }
    return;
}

void add_cache_mem_g(unsigned long x86_addr, unsigned int size)
{
    int idx;
    if (mem_g_cache.count + 1 == GLOBAL_CACHE_NUM)
    {
        warning("cache mem is filled\n");
        idx = mem_g_cache.count - 1;
    }
    else
    {
        idx = atomic_fetch_add(&(mem_g_cache.count), 1);
    }
    mem_g_cache.x86_addr[idx] = x86_addr;
    mem_g_cache.size[idx] = size;
    // !!! no need
    // update_write_cache_mem(x86_addr, size);
    // debug6("read ADD cache_addr(%#lx) cache_size (%d) total count (%d)\n", x86_addr, size, mem_g_cache.count);
    return;
}

#define WRITE_MERGE_F 0xffff

static int access_write_mem(unsigned long x86_addr, unsigned int cache_size, unsigned char attr)
{
    if (cache_size < CACHE_SIZE_MUSK)
    {
        return -1;
    }

    unsigned char hit_flag = attr & HIT_WRITE;
    for (int j = mem_w_cache.count - 1; j >= 0; j--)
    {
        if (x86_addr == mem_w_cache.x86_addr[j])
        {
            // return j;
            return WRITE_MERGE_F;
        }
        else if ((mem_w_cache.attr[j] & HIT_WRITE) && hit_flag)
        {
            // todo merge the different address
            if ((x86_addr >> CACHE_SIZE_BIT_NUM) == (mem_w_cache.x86_addr[j] >> CACHE_SIZE_BIT_NUM))
            {
                // debug6("update x86(%#lx)idx(%d)\n", mem_w_cache.x86_addr[j], j);
                if (mem_w_cache.data[j] == EVERY_CACHE_SIZE)
                {
                    return WRITE_MERGE_F;
                }
                mem_w_cache.x86_addr[j] = (x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM;
                mem_w_cache.data[j] = EVERY_CACHE_SIZE;
                mem_w_cache.attr[j] = CACHE_SIZE_WRITE | HIT_WRITE;
                return WRITE_MERGE_F;
            }
        }
    }
    return -1;
}
// static pthread_spinlock_t test_mutex2 = SPINLOCK_INIT_ARM;
static void add_cache_write_mem(struct ADDR_MAP *ad_map, unsigned long x86_addr, unsigned long data, unsigned char attr)
{
    // int idx = access_write_mem(x86_addr, data, attr);
    // !!!!! pathc todo
    int idx = -1;
    if (idx == WRITE_MERGE_F)
    {
        return;
    }

    if (mem_w_cache.count + 1 == CACHE_WRITE_NUM)
    {
        warning("cache write mem is full\n");
        idx = mem_w_cache.count - 1;
    }

    // pthread_spin_lock(&test_mutex2);
    idx = atomic_fetch_add(&(mem_w_cache.count), 1);
    // __sync_synchronize();
    mem_w_cache.addr_map[idx] = (unsigned long)ad_map;
    mem_w_cache.x86_addr[idx] = x86_addr;
    mem_w_cache.attr[idx] = attr;
    if (attr & HIT_WRITE)
    {
        // !!! patch
        mem_w_cache.data[idx] = 8;
    }
    // __sync_synchronize();
    // debug6("write ADD cache_addr(%#lx) arm (%#lx) total count (%d)\n", mem_w_cache.x86_addr[idx], ad_map->arm_addr, idx);
    // pthread_spin_unlock(&test_mutex2);

    return;
}

void flush_cache_mem()
{
    mem_g_cache.count = 0;
    mem_w_cache.count = 0;
    return;
}

static pthread_spinlock_t test_mutex = SPINLOCK_INIT_ARM;

static struct ADDR_MAP *add_addr_map(unsigned long x_addr, unsigned long a_addr, unsigned long xq_addr, int page_count, int other)
{
    struct ADDR_MAP *ad_map = malloc(sizeof(struct ADDR_MAP));
    ad_map->x86_addr = x_addr;
    ad_map->arm_addr = a_addr;
    ad_map->size = page_count * ADDR_MAP_UNIT_SIZE;
    ad_map->attr = other;
    ad_map->doca_buf_ptr = get_r_doca_buf_list(x_addr, 1 * ADDR_MAP_UNIT_SIZE);
    int index = HASH_GET_INDEX(x_addr);
    unsigned long temp = atomic_exchange((unsigned long *)&(map_list[index]), (unsigned long)ad_map);
    ad_map->next = (struct ADDR_MAP *)temp;
    return ad_map;
}

void add_new_mmap(unsigned long x86_addr)
{
    struct mmap_range_list *tmp_doca_map = get_remote_mmap_range_by_addr(x86_addr);
    if (tmp_doca_map == NULL)
    {
        // !!! add mutex
        LOCK_OFD_MSG;
        if (get_remote_mmap_range_by_addr(x86_addr) != NULL)
        {
            UNLOCK_OFD_MSG;
            goto LABEL_RET;
        }
        // waiting last finish
        while (d_ofd_code_addr->direct == D_TO_CLIENT)
        {
            sync_ofd_msg_from(OFD_CODE_MSG_BUF_SIZE2);
        }

        d_ofd_code_addr->flag = MAP_NEW_ADDR;
        d_ofd_code_addr->direct = D_TO_CLIENT;
        *(unsigned long *)(d_ofd_code_addr->data) = x86_addr;
        sync_ofd_msg_to(OFD_CODE_MSG_BUF_SIZE2);
        // ! only debug
        debug4("waiting client addr(%#lx) d_ofd(%#lx)\n", x86_addr, d_ofd_code_addr);

        while (d_ofd_code_addr->direct != D_TO_SERVER)
        {
            // debug4("d_ofd_code_addr->direct(%d)\n",d_ofd_code_addr->direct);
            sync_ofd_msg_from(OFD_CODE_MSG_BUF_SIZE2);
        }
        debug4("client finished\n");
        assert(d_ofd_code_addr->flag == F_SET_REMOTE_MMAP_RANGE);
        bool res = gen_memory_range_from_export_json(d_ofd_code_addr->data);
        if (res == false)
        {
            info("remote doca mmap range build failed\n");
        }
        // reply the client
        d_ofd_code_addr->direct = D_SERVER_FIN;
        UNLOCK_OFD_MSG;
    }
LABEL_RET:
    return;
}

static pthread_spinlock_t mutex_malloc_onpage = SPINLOCK_INIT_ARM;
static void *free_end = NULL;

void *ofd_mmu_malloc_onepgage(int count)
{
    unsigned long temp;
    if (free_mmu == NULL) // || (free_mmu >= free_end + count * PAGE_SIZE && free_end != NULL)
    {
        warning("malloc new mmu malloc pages\n");
        pthread_spin_lock(&mutex_malloc_onpage);
        if (free_mmu != NULL)
        {
            pthread_spin_unlock(&mutex_malloc_onpage);
            goto RET_LABEL;
        }

        free_mmu = malloc_mem_pool(MMU_PAGE_SIZE * PAGE_SIZE);
        temp = (unsigned long)free_mmu;
        for (int i = 0; i < (MMU_PAGE_SIZE / (ADDR_MAP_UNIT_SIZE / PAGE_SIZE)) - 1; i++)
        {
            *((unsigned long *)temp) = temp + ADDR_MAP_UNIT_SIZE;
            temp += ADDR_MAP_UNIT_SIZE;
        }
        *((unsigned long *)temp) = NULL;
        // free_end = (char *)((unsigned long)free_mmu + MMU_PAGE_SIZE * PAGE_SIZE);
        pthread_spin_unlock(&mutex_malloc_onpage);
    }
RET_LABEL:
    temp = atomic_fetch_add((unsigned long *)&free_mmu, count * PAGE_SIZE);
    // free_mmu = (void *)*((unsigned long *)free_mmu);
    // debug6("mem(%#lx)\n",temp);
    return (void *)temp;
}

void ofd_mmu_free_onepgage(unsigned long addr)
{
    if (free_mmu == NULL)
    {
        free_mmu = addr;
        *((unsigned long *)addr) = NULL;
    }
    else
    {
        *((unsigned long *)addr) = (unsigned long)free_mmu;
        free_mmu = addr;
    }
    return;
}

// ! patch
static pthread_spinlock_t mutex_add_mmu = SPINLOCK_INIT_ARM;
static unsigned int todo_addr[2];

//  return
// @value NULL --> means nothing will be in
// @value is non-null --> correct the struture
struct ADDR_MAP *find_addr_map(unsigned long x86_addr)
{
    int index = HASH_GET_INDEX(x86_addr);
    struct ADDR_MAP *temp_map = map_list[index];
    while (temp_map != NULL)
    {
        if (temp_map->x86_addr <= x86_addr && x86_addr < temp_map->x86_addr + temp_map->size)
        {
            return temp_map;
        }
        temp_map = temp_map->next;
    }

    pthread_spin_lock(&mutex_add_mmu);
    // deal with the remote mmap
    // debug4("from mem x86_addr(%#lx)\n", x86_addr);
    if ((todo_addr[0] == ((x86_addr >> 12) & 0xffffff)))
    {
        // while (true)
        // {
        temp_map = map_list[index];
        while (temp_map != NULL)
        {
            if (temp_map->x86_addr <= x86_addr && x86_addr < temp_map->x86_addr + temp_map->size)
            {
                pthread_spin_unlock(&mutex_add_mmu);
                return temp_map;
            }
            temp_map = temp_map->next;
        }
        // debug6("loop");
        warning("why no mmu data?\n");
        // }
    }
    todo_addr[0] = ((x86_addr >> 12) & 0xffffff);
    // todo! add lock in order for multi-threads
    add_new_mmap(x86_addr);
    void *arm_addr = ofd_mmu_malloc_onepgage(1);
    temp_map = add_addr_map((x86_addr >> 12) << 12, arm_addr, x86_addr, 1, F_M_INIT);
    // }
    // debug6("map x86(%#lx)arm(%#lx)\n", x86_addr, arm_addr);
    pthread_spin_unlock(&mutex_add_mmu);
    return temp_map;
}


void copy_write_remote_mem(struct ADDR_MAP *ad_map, unsigned long x86_addr, int size, int threadid)
{
    doca_mem_copy_from(ad_map->doca_buf_ptr, x86_addr, off_thread_write_buf_arr[threadid], size, DMA_SYNC);
    return;
}

// this function don't need lock
void read_remote_mem(struct ADDR_MAP *ad_map, unsigned long arm_addr, int size, int cache)
{
    unsigned long x86_addr = (arm_addr - ad_map->arm_addr) + ad_map->x86_addr;

#ifdef DEMO_SERVER
    if (cache == 0xbeed)
    {
        if (--batch == 0)
        {
            doca_mem_copy_to(ad_map->doca_buf_ptr, x86_addr, arm_addr, 8, true);
            doca_mem_copy_from(ad_map->doca_buf_ptr, x86_addr, arm_addr, 8, DMA_SYNC);
            batch = BATCH_SIZE;
        }
        return;
    }
#endif
    int res = access_cache_mem_g(x86_addr, size);
    if (res == MISS)
    {
        // cache = 0x19
        if (cache == READ_Q_CODE_V2)
        {
            size = 128;
            doca_mem_copy_from(ad_map->doca_buf_ptr, x86_addr - 64, arm_addr - 64, size, DMA_SYNC | DMA_CB_F_ADD_CACHE_G);
            // add_cache_mem_g(x86_addr - 64, size);
            debug4("MISS: arm(%#lx) x86_addr(%#lx) data(%#lx) size(%d) \n", arm_addr, x86_addr, *((unsigned long *)arm_addr), size);
        }
        else if (cache == READ_PREFETCH_ASYNC)
        {
            // size = 0x400;
            // doca_mem_copy_from(ad_map->doca_buf_ptr, x86_addr - 0x254, arm_addr - 0x254, size, true);
            // add_cache_mem_g(x86_addr - 0x254, size);
            // debug4("MISS: arm(%#lx) x86_addr(%#lx) data(%#lx) size(%d) \n", arm_addr, x86_addr, *((unsigned long *)arm_addr), size);
            // !!! todo those code maybe result out-of-bounds read/write
            //? size += (x86_addr & CACHE_SIZE_MUSK);
            if (size < EVERY_CACHE_SIZE)
            {
                size = EVERY_CACHE_SIZE;
            }
            doca_mem_copy_from(ad_map->doca_buf_ptr, ((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), ((arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), size, DMA_ASYNC | DMA_CB_F_ADD_CACHE_G);
            // add_cache_mem_g((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
            debug4("MISS: arm(%#lx) x86_addr(%#lx) data(%#lx) size(%d) \n", arm_addr, x86_addr, *((unsigned long *)arm_addr), size);
        }
        else
        {
            // !!! todo those code maybe result out-of-bounds read/write
            //? size += (x86_addr & CACHE_SIZE_MUSK);
            if (size < EVERY_CACHE_SIZE)
            {
                size = EVERY_CACHE_SIZE;
            }
            // sync_mem_from(ad_map, ((arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), size);
            doca_mem_copy_from(ad_map->doca_buf_ptr, ((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), ((arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), size, DMA_SYNC | DMA_CB_F_ADD_CACHE_G);
            // doca_mem_copy_from(ad_map->doca_buf_ptr, (((arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM) - ad_map->arm_addr) + ad_map->x86_addr, ((arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM), size, true);
            // add_cache_mem_g((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
            debug4("MISS: arm(%#lx) x86_addr(%#lx) data(%#lx) size(%d) \n", arm_addr, x86_addr, *((unsigned long *)arm_addr), size);
        }
    }
    else if (res == SYNC_F)
    {
        size += (x86_addr & CACHE_SIZE_MUSK);
        if (size < EVERY_CACHE_SIZE)
        {
            size = EVERY_CACHE_SIZE;
        }
        for (int i = 0; i < FETCH_TEST_NUM; i++)
        {
            // try to access the synchronization point
            sync_mem_from(ad_map, (arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
            if (*((unsigned long *)arm_addr) != 0)
            {
                add_cache_mem_g((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
                // debug6("arm_addr(%#lx)data(%#lx)\n", arm_addr, *((unsigned long *)arm_addr));
                atomic_fetch_add(&start_write_threads, 1);
                break;
            }

            // access mem_cache
            //  mem_cache --> hit:(checkpoint) miss:(sync_copy_from->checkpoint)
            // checkpoint --> yes:(jump out)     no:(waiting condition in start_write_thread args)
            while (atomic_load(&sync_write_flag) != 1)
                ;

            // need to mutex accessing
            pthread_spin_lock(&test_mutex);
            if (access_cache_mem_g(x86_addr, size) != HIT)
            {
                sync_mem_from(ad_map, (arm_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
            }
            pthread_spin_unlock(&test_mutex);

            if (*((unsigned long *)arm_addr) != 0)
            {
                // debug6("1arm_addr(%#lx)data(%#lx)\n", arm_addr, *((unsigned long *)arm_addr));
                add_cache_mem_g((x86_addr >> CACHE_SIZE_BIT_NUM) << CACHE_SIZE_BIT_NUM, size);
                atomic_fetch_add(&start_write_threads, 1);
                break;
            }
            else
            {
                while (atomic_load(&start_write_threads) != 0)
                    ;
            }
        }
    }
    debug4("ad_map x86(%#lx), arm(%#lx) arm_addr(%#lx) size(%x)\n", ad_map->x86_addr, ad_map->arm_addr, arm_addr, ad_map->size);
    // debug3("ret\n");
    return;
}

static void sync_mem_from(struct ADDR_MAP *ad_map, unsigned long arm_addr, int size)
{
    doca_mem_copy_from(ad_map->doca_buf_ptr, (arm_addr - ad_map->arm_addr) + ad_map->x86_addr, arm_addr, size, DMA_SYNC | DMA_CB_F_NULL);
    return;
}

static void sync_mem_to(struct ADDR_MAP *ad_map, unsigned long arm_addr, int size)
{
    doca_mem_copy_to(ad_map->doca_buf_ptr, (arm_addr - ad_map->arm_addr) + ad_map->x86_addr, arm_addr, size, true);
    return;
}

static void sync_mem_to2(struct ADDR_MAP *ad_map, unsigned long x86_addr, int size)
{
    doca_mem_copy_to(ad_map->doca_buf_ptr, x86_addr, (x86_addr - ad_map->x86_addr) + ad_map->arm_addr, size, false);
}

static void sync_mem_to_sync(struct ADDR_MAP *ad_map, unsigned long arm_addr, unsigned long data, int size)
{
    // debug5("bar sync(%#lx) size(%#x)\n",(arm_addr - ad_map->arm_addr) + ad_map->x86_addr, size);
    doca_mem_copy_to_sync(ad_map->doca_buf_ptr, (arm_addr - ad_map->arm_addr) + ad_map->x86_addr, arm_addr, size);
}

static void submit_write_remote_mem()
{
    // debug5("write count(%d)\n", mem_w_cache.count);
    for (int j = mem_w_cache.count - 1; j >= 0; j--)
    {
        // debug6("x86(%#lx) addr_map (%#lx) count (%d)\n", mem_w_cache.x86_addr[j], mem_w_cache.addr_map[j], j);
        if (mem_w_cache.attr[j] & CACHE_SIZE_WRITE)
        {
            sync_mem_to2((struct ADDR_MAP *)mem_w_cache.addr_map[j], mem_w_cache.x86_addr[j], mem_w_cache.data[j]);
        }
        else if (mem_w_cache.attr[j] & HIT_WRITE)
        {
            sync_mem_to2((struct ADDR_MAP *)mem_w_cache.addr_map[j], mem_w_cache.x86_addr[j], mem_w_cache.attr[j] & 0xf);
        }
        else if (mem_w_cache.attr[j] & MISS_WRITE)
        {
            warning("todo miss write cache\n");
            sync_mem_to2((struct ADDR_MAP *)mem_w_cache.addr_map[j], mem_w_cache.x86_addr[j], mem_w_cache.attr[j] & 0xf);
        }
        mem_w_cache.x86_addr[j] = 0;
    }
    mem_w_cache.count = 0;
}

static pthread_mutex_t mutex_lock_sync = PTHREAD_MUTEX_INITIALIZER;

void mem_bar_sync_to(struct ADDR_MAP *ad_map, unsigned long arm_addr, unsigned long data, int size)
{
    if (atomic_fetch_add(&in_write_threads, 1) == 0)
    {
        sync_write_flag = 1;
    }
    // debug3("count (%d) ofd(%d)\n",in_write_threads,ofd_threads_count);
    unsigned long x86_addr = (arm_addr - ad_map->arm_addr) + ad_map->x86_addr;
    add_bar_cache_mem(x86_addr);
    pthread_mutex_lock(&mutex_lock_sync);
    // !! todo fix ofd_threads_count and in write_threads
    while (sync_write_flag && (atomic_load(&in_write_threads) != ofd_threads_count) && (atomic_load(&in_write_threads) < start_write_threads))
        ;
    // TODO this two code should be execute once time
    if (sync_write_flag)
    {
        //!!! patch sync
        // *((unsigned long *)arm_addr) = 0xff;
        submit_write_remote_mem();
        flush_cache_mem();
        // !!! patch
        // *((unsigned long *)arm_addr) = data;
        sync_mem_to_sync(ad_map, (arm_addr >> 8) << 8, data, 256);
        sync_write_flag = 0;
        start_write_threads = 0;
    }

    pthread_mutex_unlock(&mutex_lock_sync);
    atomic_fetch_sub(&in_write_threads, 1);
    return;
}

static unsigned char gen_cache_write_att(int flag)
{
    switch (flag)
    {
    case WRITE_Q_CODE:
        return QUADRA_WORD;
    case WRITE_D_CODE:
        return DOUBLE_WORD;
    case WRITE_B_CODE:
        return HALF_WORD;
    default:
        error("error FLAG(%d)\n", flag);
        break;
    }
    return 0;
}

void write_remote_mem(struct ADDR_MAP *ad_map, unsigned long arm_addr, unsigned long data, int flag)
{
    // debug4("int\n");
    unsigned long x86_addr = (arm_addr - ad_map->arm_addr) + ad_map->x86_addr;
    int res = access_cache_mem_g2(x86_addr, QUADRA_WORD);
    unsigned char att = gen_cache_write_att(flag);
    if (res != MISS)
    {
        add_cache_write_mem(ad_map, x86_addr, res, HIT_WRITE | att);
        switch (flag)
        {
        case WRITE_Q_CODE:
            *((unsigned long *)arm_addr) = data;
            break;
        case WRITE_D_CODE:
            *((unsigned int *)arm_addr) = data & 0xffffffff;
            break;
        case WRITE_B_CODE:
            *((unsigned char *)arm_addr) = data & 0xff;
            break;
        default:
            error("error FLAG(%d)\n", flag);
            break;
        }
    }
    else
    {
        warning("miss write remote addr\n");
        add_cache_write_mem(ad_map, x86_addr, data, MISS_WRITE | att);
    }
}
