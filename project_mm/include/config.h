#define REDIS_SERVER


#ifdef REDIS_SERVER
// !!! modify by mtcp
// #define UIO_MODE
#define IO_MAIN_THREADS_NAME "IOThreadMain"
#endif

#define DPU_IP "192.168.100.2"
#define DPU_PORT 6666
#define DPU_CPU_FREQ 2000000000.0

#define PCI_BUF_SIZE 13
#ifdef __x86_64__
// #define PCI_BUS_ADDR 0x21
#define PCI_BUS_ADDR "21:00.0"
#else
// #define PCI_BUS_ADDR 0x03
#define PCI_BUS_ADDR "03:00.0"
#endif
// #define REP_PCI_BUS_ADDR {.bus = 0x21, .device = 0, .function = 0};
#define REP_PCI_BUS_ADDR "21:00.0"

#define PAGE_SIZE 4096
#define C_DOCA_MMAP_NAME "REDIS_MMAP"
#define S_DOCA_MMAP_NAME "REDIS_MMAP"
#define DOCA_INVENTORY_NAME "redis_inventory"
#define ELEMENT_IN_INVENTORY 200
#define DEPTH_WORKQ 1024

// communicate channel
#define MAX_MSG_SIZE 1024
#define MAX_NUM_MSGS 8000
#define HOST_CPU_FREQ 3700000000.0
#define COMM_CHANN_NAME "REDIS_CHANNEL"

// DPU max chunks in mmap
#define MMAP_MAX_NUM_CHUNKS 50

#define SHARE_COM_BUF_SIZE 1024

#define SERVER_MALLOC_ALIGIN 0x100

// permission in mmap
#define PER_READ 1
#define PER_WRITE 2

#define MTCP_MODE

#ifdef UIO_MODE

#define FD_OFFSET 0
#define FD_ST_IN_DPU 500
#define READ_BUF_FD_ST 507

#else
// ! patch for mtcp
#define FD_OFFSET 500
#define TEMP_ANNOTATION
#define FD_ST_IN_DPU 500
// ! patch for mtcp socket fd start from 0 old value: 507
#define READ_BUF_FD_ST 501
#endif

//  only test the sync_from performance
// #define TEST_SYNC_FROM

// config DPU io threads number
#define MAX_DPU_IO_THREADS_NUM 4

#define DPU_STRUCT_EPOLL_SIZE 16
#define HSOT_STRUCT_EPOLL_SIZE 12

// !!! MUST BE AN EVEN
// #define MAX_EVENTS_NUM 6
// #define MAX_READ_ADDR_NUM 50
#define MAX_READ_ADDR_NUM 25
#define READ_BUF_SIZE 0x4000000
#define WRITE_BUF_SIZE 0x4000000
#define MAX_EPOLL_EVENT_NUM 400
#define MAX_FD_NUM 400
#define SYNC_FD_SIZE 400

// for offload thread write buf
#define W_BUF_S_ONCE 65536

#define FREE_FLAG_BIT 0x100000
#define READ_CHUNK_SIZE_MUST 0x0fffff

#define WRITE_LITTLE_DATA_SIZE 100

#define OFD_CODE_MSG_BUF_SIZE 1536
#define OFD_CODE_MSG_BUF_SIZE2 512
#define OFD_MSG_BUF_SIZE_TOTAL 2048
#define OFD_MSG_DATA_SIZE 1480
#define OFD_MSG_DATA_SIZE2 400

#define DPU_MEM_POOL_SIZE (1020 * 1024 * 1024)
#define X86_MEM_BUF_POOL_LEN (1020 * 1024 * 1024)
// #define UIO_MODE

// ***************************************

// MTCP config
#ifndef MAX_CPUS
#define MAX_CPUS 4
#endif
// !!! MAX_CPUS
#define MTCP_THREAD_NUM 4
// !!! patch  (coreid * (MAX_FD_NUM / (MAX_CPUS - 1)) + fd + FD_OFFSET) : (coreid * (MAX_FD_NUM / CORE_LIMIT) + fd + FD_OFFSET)
#define MASTER_CORE_THREAD 0
#define FD_MAPPING(coreid, fd) (coreid * (MAX_FD_NUM / (MAX_CPUS)) + fd + FD_OFFSET)
#define MAP_FD_GET_FD(fd) ((fd - FD_OFFSET) % (MAX_FD_NUM / (MAX_CPUS)))
#define MAP_FD_GET_COREID(fd) ((fd - FD_OFFSET) / (MAX_FD_NUM / (MAX_CPUS)))

// ***************************************

#ifndef __x86_64__
#define BARRIER asm volatile("DSB SY" :: \
                                 : "memory");
#else
#define BARRIER \
    {           \
    }
#endif

#define SPINLOCK_INIT_X86 1
#define SPINLOCK_INIT_ARM 0

// #define DEBUG
// #define DEBUG2
// #define DEBUG3
// #define DEBUG4
// #define HAPROXY_WRITE_DISTRUBUTE

// #define LHTTPD_WRITE_DISTRUBUTE
#define HA_NO_NEED
