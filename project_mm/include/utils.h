#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include "config.h"

#ifndef __x86_64__

#define ARMV8_PMCR_E (1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P (1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C (1 << 2) /* Cycle counter reset */

#define ARMV8_PMUSERENR_EN (1 << 0) /* EL0 access enable */
#define ARMV8_PMUSERENR_CR (1 << 2) /* Cycle counter read enable */
#define ARMV8_PMUSERENR_ER (1 << 3) /* Event counter read enable */

#define ARMV8_PMCNTENSET_EL0_EN (1 << 31) /* Performance Monitors Count Enable Set register */

static inline uint64_t get_cpu_cycle_count(void)
{
    uint64_t result = 0;

    asm volatile("MRS %0, PMCCNTR_EL0"
                 : "=r"(result));

    return result;
}

static inline void arm_v8_timing_init(void)
{
    uint32_t value = 0;

    /* Enable Performance Counter */
    asm volatile("MRS %0, PMCR_EL0"
                 : "=r"(value));
    value |= ARMV8_PMCR_E; /* Enable */
    value |= ARMV8_PMCR_C; /* Cycle counter reset */
    value |= ARMV8_PMCR_P; /* Reset all counters */
    asm volatile("MSR PMCR_EL0, %0"
                 :
                 : "r"(value));

    /* Enable cycle counter register */
    asm volatile("MRS %0, PMCNTENSET_EL0"
                 : "=r"(value));
    value |= ARMV8_PMCNTENSET_EL0_EN;
    asm volatile("MSR PMCNTENSET_EL0, %0"
                 :
                 : "r"(value));
}

static inline void arm_v8_timing_terminate(void)
{
    uint32_t value = 0;
    uint32_t mask = 0;

    /* Disable Performance Counter */
    asm volatile("MRS %0, PMCR_EL0"
                 : "=r"(value));
    mask = 0;
    mask |= ARMV8_PMCR_E; /* Enable */
    mask |= ARMV8_PMCR_C; /* Cycle counter reset */
    mask |= ARMV8_PMCR_P; /* Reset all counters */
    asm volatile("MSR PMCR_EL0, %0"
                 :
                 : "r"(value & ~mask));

    /* Disable cycle counter register */
    asm volatile("MRS %0, PMCNTENSET_EL0"
                 : "=r"(value));
    mask = 0;
    mask |= ARMV8_PMCNTENSET_EL0_EN;
    asm volatile("MSR PMCNTENSET_EL0, %0"
                 :
                 : "r"(value & ~mask));
}

static inline void arm_v8_reset_timing(void)
{
    uint32_t value = 0;
    asm volatile("MRS %0, PMCR_EL0"
                 : "=r"(value));
    value |= ARMV8_PMCR_C; /* Cycle counter reset */
    asm volatile("MSR PMCR_EL0, %0"
                 :
                 : "r"(value));
}

#else

static inline uint64_t get_cpu_cycle_count()
{
    uint64_t rax, rdx;
    asm volatile("rdtscp\n"
                 : "=a"(rax), "=d"(rdx)::"%rcx", "memory");
    return (rdx << 32) | rax;
}

static inline void arm_v8_timing_init(void)
{
    return;
}
static inline void arm_v8_timing_terminate(void)
{
    return;
}

static inline void arm_v8_reset_timing(void)
{
    return;
}

#endif

#define COLOR_RESET "\033[0m"

#ifdef DEBUG
#define debug(fmt, ...)                                                                                                                       \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug(...)
#endif

#ifdef DEBUG2
#define debug2(fmt, ...)                                                                                                                      \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug2(...)
#endif

#ifdef DEBUG3
#define debug3(fmt, ...)                                                                                                                      \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug3(...)
#endif

// #define DEBUG4
#ifdef DEBUG4
#define debug4(fmt, ...)                                                                                                                      \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug4(...)
#endif

// #define DEBUG5
#ifdef DEBUG5
#define debug5(fmt, ...)                                                                                                                      \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug5(...)
#endif

// #define DEBUG6
#ifdef DEBUG6
#define debug6(fmt, ...)                                                                                                                      \
    do                                                                                                                                        \
    {                                                                                                                                         \
        fprintf(stdout, "\033[0;34m%s:\033[0;31m%d:\033[0;33m%s() \033[0;32m " fmt COLOR_RESET, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)
#else
#define debug6(...)
#endif

#define info(fmt, ...)                                                                       \
    do                                                                                       \
    {                                                                                        \
        fprintf(stdout, "\033[0;34m%s \033[0;32m" fmt COLOR_RESET, __func__, ##__VA_ARGS__); \
    } while (0)

#define error(fmt, ...)                                                                 \
    do                                                                                  \
    {                                                                                   \
        fprintf(stdout, "\033[0;31mE: [%s] " fmt COLOR_RESET, __func__, ##__VA_ARGS__); \
    } while (0)

#define warning(fmt, ...)                                                               \
    do                                                                                  \
    {                                                                                   \
        fprintf(stdout, "\033[0;35mW: [%s] " fmt COLOR_RESET, __func__, ##__VA_ARGS__); \
    } while (0)

#ifndef __x86_64__

// those instruction access memory must align
#define ATOM_READ_INT(addr, data) \
    asm volatile("LDAR %0, [%1]"  \
                 : "=r"(data)     \
                 : "r"(addr));

#else

#define ATOM_READ_INT(addr, data) \
    data = (int *)addr[0];

#endif

#define F_COM_BUF_SHARE 10
#define F_MEMCPY_TO_CLIENT 11
#define F_MEMCPY_TO_SERVER 12
#define F_SIMULATE_FUNTION 13
#define F_SET_REMOTE_MMAP_RANGE 14
#define F_TEST_MEMORY 15
#define F_SET_EPOLL_MEMORY 16
#define F_GET_OFFCODE_SWITCH_ADDR 17
#define F_ARM_BIN_DATA 18
#define F_OFFLOAD_IO_THREAD 19

#define D_TO_CLIENT 1
#define D_TO_SERVER 2
#define D_CLIENT_FIN 3
#define D_SERVER_FIN 4

#define T_FUN_SOCKET 1
#define T_FUN_BIND 2
#define T_FUN_LISTEN 3
#define T_FUN_ACCEPT 4
#define T_FUN_SETSOCKOPT 5
#define T_FUN_READ 6
#define T_FUN_WRITE 7
#define T_FUN_CONNECT 8
#define T_FUN_CLOSE 9
#define T_FUN_GETADDRINFO 10
#define T_FUN_EPOLL_CTL 11
#define T_FUN_EPOLL_WAIT 12
#define T_FUN_EPOLL_CREATE 13
#define T_FUN_POLL 14
#define T_FUN_FCNTL 15
#define T_FUN_PTHREAD_CREATE 16
#define T_FUN_RECV 17
#define T_FUN_SEND 18
#define T_FUN_IOCTL 19

#define FUN_WRITE_RING_FLAG 0xf0
#define FUN_WRITE_DATA_FLAG 0xf1

// !!! the control data must be later
struct CMD_MSG
{
    volatile unsigned long arg1;
    volatile unsigned long arg2;
    volatile unsigned long arg3;
    volatile unsigned long arg4;
    volatile unsigned long arg5;
    volatile unsigned int type;     // function type, predefine
    volatile unsigned short flag;   // maybe memcpy_to_client or memcpy_to_server or simulate function
    volatile unsigned short direct; // maybe C S S-F C-F
    volatile unsigned char data[160];
};

// MEM management
extern volatile struct CMD_MSG *sync_ctrl_cmd;

struct EP_EVENT_ARM
{
    uint64_t events;
    uint64_t u64;
};

struct FD_READ_ED
{
    volatile unsigned int ed_r_addr_i;
    unsigned int read_addr_buf[MAX_READ_ADDR_NUM];
};

struct FD_READ_ST
{
    volatile unsigned int st_r_addr_i;
};

// !!! the control data must be later
#define RING_ED_HEADER_SIZE 12
struct RING_INFO_ED
{
    struct FD_READ_ED read_addr_inv[MAX_FD_NUM];
    volatile unsigned int ed_ep_en_off;
    volatile unsigned int ed_read_buf_off[MTCP_THREAD_NUM];
    volatile unsigned int st_write_buf_off;
};

// ! it's related to sync size
#define RING_ST_HEADER_SIZE 12
struct RING_INFO_ST
{
    volatile unsigned int st_ep_en_off;
    // !!! MAX_CPUS patching
    volatile unsigned int st_read_buf_off[MTCP_THREAD_NUM];
    volatile unsigned int ed_write_buf_off;
    struct FD_READ_ST read_st_index[MAX_FD_NUM];
};

struct RING_HEADER
{
    volatile int flag;
    volatile int lens;
};

#define W_NO_DATA 0
#define W_PENDING 1
#define W_WRITE_FLAG 2
#define W_CMD_FLAG 3

#define ALIGIN_SIZE 32
#define ALIGIN_BITS 4


#endif
