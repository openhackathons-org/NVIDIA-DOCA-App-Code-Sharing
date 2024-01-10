#ifndef _MEM_MAP_H
#define _MEM_MAP_H
#include <pthread.h>
struct ADDR_MAP
{
    unsigned long x86_addr;
    unsigned long arm_addr;
    unsigned long doca_buf_ptr;
    unsigned int size;
    unsigned int attr;
    struct ADDR_MAP* next;
};

#define F_M_NEW_WRITE 0x1
#define F_M_NEW_READ 0x2
#define F_M_INIT 0x3
#define F_M_STACK 0x4
#define F_M_NEW_SYNC_TO 0x5
#define F_M_NEW_SYNC_FROM 0x6

void read_remote_mem(struct ADDR_MAP *ad_map, unsigned long aim_addr, int size, int cache);
void copy_write_remote_mem(struct ADDR_MAP *ad_map, unsigned long arm_addr, int size, int threadid);
void mem_bar_sync_to(struct ADDR_MAP *ad_map, unsigned long arm_addr, unsigned long data, int size);
void write_remote_mem(struct ADDR_MAP *ad_map, unsigned long arm_addr,unsigned long data,  int size);
struct ADDR_MAP *find_addr_map(unsigned long x86_addr);
void add_cache_mem_g(unsigned long x86_addr, unsigned int size);
extern pthread_spinlock_t mutex_ofd_msg;
#define LOCK_OFD_MSG pthread_spin_lock(&mutex_ofd_msg)
#define UNLOCK_OFD_MSG pthread_spin_unlock(&mutex_ofd_msg)
#define TRYLOCK_OFD_MSG pthread_spin_trylock(&mutex_ofd_msg)
extern int sync_write_flag;
extern int start_write_threads;
#endif