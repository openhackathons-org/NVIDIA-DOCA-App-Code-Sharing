#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#include <utils.h>
#include <doca_log.h>
#include <doca_argp.h>
#include <doca_flow.h>
#include <dpdk_utils.h>
#include <doca_flow_net.h>
#include <offload_rules.h>

#define MAX_LCORE 8
#define NB_MBUF 1024
#define BURST_SIZE 32
#define BUF_SIZE 2048
#define MAX_QUEUES 16
#define MAX_ETHPORTS 16
#define MAX_PORT_STR 128
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 1518
#define MEMPOOL_CACHE_SIZE 256
#define MAX_MBUFS_PER_PORT 16384
#define MBUF_SIZE (BUF_SIZE + RTE_PKTMBUF_HEADROOM)
#define TIMEVAL_TO_MSEC(t) ((t.tv_sec * 1000) + (t.tv_usec / 1000))
#define OFF_MF 0x2000
#define OFF_MASK 0x1fff

DOCA_LOG_REGISTER(L2FWD);

struct core_conf
{
    int ports[2];
    int queues[2];
    bool used;
};

struct l2fwd_ft_key
{
    uint32_t rss_hash;
};

struct l2fwd_pkt_info
{
    void *orig_data;
    uint16_t orig_port_id;
    uint16_t pipe_queue;
    uint32_t rss_hash;
};

struct l2fwd_ft_user_ctx
{
    uint32_t fid;
    uint8_t data[0];
};

struct l2fwd_ft_entry
{
    LIST_ENTRY(l2fwd_ft_entry)
    next; /* entry pointers in the list. */
    struct l2fwd_ft_key key;
    uint64_t expiration;
    uint64_t last_counter;
    uint64_t sw_ctr;
    uint8_t hw_off;
    uint16_t buckets_index;
    struct l2fwd_ft_user_ctx user_ctx;
};
LIST_HEAD(l2fwd_ft_entry_head, l2fwd_ft_entry);

struct l2fwd_pipe_entry
{
    bool is_hw;
    uint64_t total_pkts;
    uint64_t total_bytes;
    struct doca_flow_pipe_entry *hw_entry;
};

struct l2fwd_config
{
    struct application_dpdk_config *dpdk_cfg;
    uint16_t rx_only;
    int stats_timer;
};

struct l2fwd_process_pkts_params
{
    struct l2fwd_config *cfg;
    struct app_vnf *vnf;
};

struct app_vnf
{
    int (*vnf_init)(struct application_port_config *port_cfg);
    int (*vnf_process_pkt)(struct l2fwd_pkt_info *pinfo);
    int (*vnf_destroy)(void);
};

static volatile bool force_quit;
struct core_conf core_confs[MAX_LCORE];
struct doca_flow_port *fwd_ports[MAX_ETHPORTS];
struct doca_flow_fwd *fwd_tbl_port[MAX_ETHPORTS];
struct doca_flow_fwd *sw_rss_fwd_tbl_port[MAX_ETHPORTS];

struct doca_flow_pipe *F[4];
struct doca_flow_pipe *FB[4];
// 添加数据结构
struct timespec C_time = {0, 0};
struct timespec P_time = {3, 0};
uint64_t ns;
uint64_t tem_token;
int nb_meters = 64;
int nb_counters = 64;
struct doca_flow_pipe *control_pipe;
struct doca_flow_pipe_entry *entry;
;
struct doca_flow_pipe_entry *entry1[4];
struct doca_flow_pipe_entry *entry2[4];
int nport = 0; // 应该在main中用dpdk传值
// struct doca_flow_pipe_entry *entry11;//port 1

int flag;

int flag1 = 0;
int flag2 = 0;
struct doca_flow_query query_stats;
struct doca_flow_query query_stats_last;
struct doca_flow_query query_stats_v1;
struct doca_flow_query query_stats_v1_last;
uint64_t ns;
struct doca_flow_query query_stats_v2;
struct doca_flow_query query_stats_v2_last;

struct doca_flow_query query_stats_v3;
struct doca_flow_query query_stats_v3_last;

struct doca_flow_pipe *pipe1;
struct doca_flow_pipe *fwd_pipe1;

int node_num = 3;
// 根据A节点的按比例分配可以实现权重
uint64_t Token[4] = {2625000000, 2625000000, 2625000000, 2625000000}; // 节点数量

uint64_t token_total;
double token[4] = {};

double P_token[4] = {};
double To_Re = 0;
double P1_token[4] = {};
double P2_token[4] = {};
double count = 0;
double temp = 0;

// get nic static
char data1[100] = {'0'};
char data2[100] = {'0'};
char data3[100] = {'0'};
char data0[100] = {'0'};
FILE *fp0 = NULL;
FILE *fp1 = NULL;
FILE *fp2 = NULL;
FILE *fp3 = NULL;
double nic_speed[4] = {0, 0, 0, 0};
long int nic_byte[4] = {0, 0, 0, 0};
long int nic_pbyte[4] = {0, 0, 0, 0};

typedef struct node
{
    char name[10];
    double set_data;
    double now_speed;
    double sendable;
    double branch;
    struct node **children;
    double n;
    double borrowed;
    double token;
    double prio;
    double total_sendable;
} Node;

void preset(Node *node)
{
    if (node != NULL)
    {
        for (int i = 0; i < node_num; i++)
        {
            preset(node->children[i]);
        }
        if ((node->set_data == 0) || (node->branch == 1))
        {
            node->set_data = 0;
            node->now_speed = 0;
            for (int i = 0; i < node_num; i++)
            {
                node->branch = 1;
                node->set_data = node->set_data + node->children[i]->set_data;
                node->now_speed = node->now_speed + node->children[i]->now_speed;
            }
        }
        node->sendable = node->set_data - node->now_speed;
    }
}
void borrow(Node *node)
{
    if (node != NULL)
    {
        if (node->branch == 1)
        {
            node->total_sendable = 0;
            for (int i = 0; i < node_num; i++)
            {
                if (node->children[i]->sendable > 0)
                {
                    node->total_sendable = node->total_sendable + node->children[i]->sendable;
                }
            }
            To_Re = node->total_sendable + node->borrowed;
            while (To_Re > 0)
            {
                count = 0;
                for (int i = 0; i < node_num; i++)
                {
                    if ((node->children[i]->sendable + node->children[i]->set_data / 2000) > 0)
                    {
                        temp = -node->children[i]->sendable;
                    }
                    else if ((To_Re - node->children[i]->set_data / 2000) < 0)
                    {
                        temp = To_Re;
                    }
                    else
                    {
                        temp = node->children[i]->set_data / 2000;
                    }

                    if (node->children[i]->sendable < 0)
                    {
                        count++;
                        node->children[i]->borrowed = node->children[i]->borrowed + temp;
                        node->children[i]->sendable = node->children[i]->sendable + temp;
                        To_Re = To_Re - temp;
                    }
                }
                if (count == 0)
                {
                    break;
                }
            }
        }
        for (int j = 0; j < node_num; j++)
        {
            borrow(node->children[j]);
        }
    }
}
void show(Node *node)
{
    if (node != NULL)
    {
        for (int i = 0; i < node_num; i++)
        {
            show(node->children[i]);
        }
        if (node->branch == 0)
        {
            node->token = node->set_data + node->borrowed;
            printf("%s newtoken=%f\n", node->name, node->token);
            printf("%s diff=%f\n", node->name, node->token - node->set_data);
        }
        node->borrowed = 0;
    }
}

struct doca_flow_pipe *fwd_pipe2;
#define CHECK_INTERVAL 1000 /* 100ms */
#define MAX_REPEAT_TIMES 90 /* 9s (90 * 100ms) in total */
#define NS_PER_SEC 1E9
#define MEMPOOL_CACHE_SIZE 256
#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif
#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32((a << 24) + (b << 16) + (c << 8) + d))
#define SET_MAC_ADDR(addr, a, b, c, d, e, f) \
    do                                       \
    {                                        \
        addr[0] = a & 0xff;                  \
        addr[1] = b & 0xff;                  \
        addr[2] = c & 0xff;                  \
        addr[3] = d & 0xff;                  \
        addr[4] = e & 0xff;                  \
        addr[5] = f & 0xff;                  \
    } while (0)

struct rte_mempool *mbuf_pool;

static void l2fwd_port_stats_display(uint16_t port, FILE *f)
{
    uint32_t i;
    static uint64_t prev_pkts_rx[MAX_ETHPORTS];
    static uint64_t prev_pkts_tx[MAX_ETHPORTS];
    static uint64_t prev_bytes_rx[MAX_ETHPORTS];
    static uint64_t prev_bytes_tx[MAX_ETHPORTS];
    static uint64_t prev_ns[MAX_ETHPORTS];
    struct timespec cur_time;
    uint64_t diff_pkts_rx, diff_pkts_tx, diff_bytes_rx, diff_bytes_tx, diff_ns;
    uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
    struct rte_eth_stats ethernet_stats;
    struct rte_eth_dev_info dev_info;
    static const char *nic_stats_border = "########################";

    rte_eth_stats_get(port, &ethernet_stats);
    rte_eth_dev_info_get(port, &dev_info);
    fprintf(f, "\n  %s NIC statistics for port %-2d %s\n", nic_stats_border,
            port, nic_stats_border);

    fprintf(f, "  RX-packets: %-10" PRIu64 " RX-missed: %-10" PRIu64 " RX-bytes:  %-" PRIu64 "\n",
            ethernet_stats.ipackets, ethernet_stats.imissed, ethernet_stats.ibytes);
    fprintf(f, "  RX-errors: %-" PRIu64 "\n", ethernet_stats.ierrors);
    fprintf(f, "  RX-nombuf:  %-10" PRIu64 "\n", ethernet_stats.rx_nombuf);
    fprintf(f, "  TX-packets: %-10" PRIu64 " TX-errors: %-10" PRIu64 " TX-bytes:  %-" PRIu64 "\n",
            ethernet_stats.opackets, ethernet_stats.oerrors, ethernet_stats.obytes);

    fprintf(f, "\n");
    for (i = 0; i < dev_info.nb_rx_queues; i++)
    {
        printf("  ethernet_stats reg %2d RX-packets: %-10" PRIu64
               "  RX-errors: %-10" PRIu64 "  RX-bytes: %-10" PRIu64 "\n",
               i, ethernet_stats.q_ipackets[i], ethernet_stats.q_errors[i],
               ethernet_stats.q_ibytes[i]);
    }

    fprintf(f, "\n");
    for (i = 0; i < dev_info.nb_tx_queues; i++)
    {
        fprintf(stdout, "  ethernet_stats reg %2d TX-packets: %-10" PRIu64 "  TX-bytes: %-10" PRIu64 "\n",
                i, ethernet_stats.q_opackets[i], ethernet_stats.q_obytes[i]);
    }

    diff_ns = 0;
    if (clock_gettime(CLOCK_TYPE_ID, &cur_time) == 0)
    {
        uint64_t ns;

        ns = cur_time.tv_sec * NS_PER_SEC;
        ns += cur_time.tv_nsec;

        if (prev_ns[port] != 0)
            diff_ns = ns - prev_ns[port];
        prev_ns[port] = ns;
    }

    diff_pkts_rx = (ethernet_stats.ipackets > prev_pkts_rx[port])
                       ? (ethernet_stats.ipackets - prev_pkts_rx[port])
                       : 0;
    diff_pkts_tx = (ethernet_stats.opackets > prev_pkts_tx[port])
                       ? (ethernet_stats.opackets - prev_pkts_tx[port])
                       : 0;
    prev_pkts_rx[port] = ethernet_stats.ipackets;
    prev_pkts_tx[port] = ethernet_stats.opackets;
    mpps_rx = diff_ns > 0 ? (double)diff_pkts_rx / diff_ns * NS_PER_SEC : 0;
    mpps_tx = diff_ns > 0 ? (double)diff_pkts_tx / diff_ns * NS_PER_SEC : 0;

    diff_bytes_rx = (ethernet_stats.ibytes > prev_bytes_rx[port])
                        ? (ethernet_stats.ibytes - prev_bytes_rx[port])
                        : 0;
    diff_bytes_tx = (ethernet_stats.obytes > prev_bytes_tx[port])
                        ? (ethernet_stats.obytes - prev_bytes_tx[port])
                        : 0;
    prev_bytes_rx[port] = ethernet_stats.ibytes;
    prev_bytes_tx[port] = ethernet_stats.obytes;
    mbps_rx =
        diff_ns > 0 ? (double)diff_bytes_rx / diff_ns * NS_PER_SEC : 0;
    mbps_tx =
        diff_ns > 0 ? (double)diff_bytes_tx / diff_ns * NS_PER_SEC : 0;

    fprintf(f, "\n  Throughput (since last show)\n");
    fprintf(f, "  Rx-pps: %12" PRIu64 "          Rx-bps: %12" PRIu64 "\n  Tx-pps: %12" PRIu64 "          Tx-bps: %12" PRIu64 "\n",
            mpps_rx, mbps_rx * 8, mpps_tx, mbps_tx * 8);

    fprintf(f, "  %s############################%s\n", nic_stats_border,
            nic_stats_border);
}

void l2fwd_dump_port_stats(struct application_port_config *port_cfg)
{
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

    fprintf(stdout, "%s%s", clr, topLeft);
    printf("XXXXXXXXXXDDDDDDDDDDDDDDDDDXXXXXXXXXXXXXXXXXXXXXXX");
    int port_id;
    for (port_id = 0; port_id < port_cfg->nb_ports; port_id++)
    {
        doca_flow_port_pipes_dump(fwd_ports[port_id], stdout);
        l2fwd_port_stats_display(port_id, stdout);
    }
    fflush(stdout);
}

struct doca_flow_port *l2fwd_init_doca_port(int port_id, int nb_ports, int nb_queues)
{
    int i;
    char port_id_str[MAX_PORT_STR];
    struct doca_flow_port_cfg doca_cfg_port;
    struct doca_flow_port *port;
    struct doca_flow_error error = {0};

    snprintf(port_id_str, MAX_PORT_STR, "%d", port_id);
    doca_cfg_port.port_id = port_id;
    doca_cfg_port.type = DOCA_FLOW_PORT_DPDK_BY_ID;
    doca_cfg_port.devargs = port_id_str;

    port = doca_flow_port_start(&doca_cfg_port, &error);
    if (port == NULL)
    {
        DOCA_LOG_ERR("failed to start port %s", error.message);
        return NULL;
    }
    fwd_ports[port_id] = port;

    /* rss queues */
    struct doca_flow_fwd *rss_fwd = calloc(1, sizeof(struct doca_flow_fwd));
    if (!rss_fwd)
    {
        DOCA_LOG_ERR("falied to allocate fwd");
        return NULL;
    }
    sw_rss_fwd_tbl_port[port_id] = rss_fwd;
    uint16_t *queues = malloc(sizeof(uint16_t) * nb_queues);
    for (i = 0; i < nb_queues; i++)
        queues[i] = i;
    rss_fwd->type = DOCA_FLOW_FWD_RSS;
    rss_fwd->rss_queues = queues;
    rss_fwd->rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
    rss_fwd->num_of_queues = nb_queues;
    rss_fwd->rss_mark = 5;
    return port;
}

void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        DOCA_LOG_INFO("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static void l2fwd_process_offload(struct rte_mbuf *mbuf, uint16_t queue_id, struct app_vnf *vnf)
{
    struct l2fwd_pkt_info pinfo;

    memset(&pinfo, 0, sizeof(struct l2fwd_pkt_info));

    pinfo.orig_data = mbuf;
    pinfo.orig_port_id = mbuf->port;
    pinfo.pipe_queue = queue_id;
    pinfo.rss_hash = mbuf->hash.rss;

    vnf->vnf_process_pkt(&pinfo);
}

struct doca_flow_pipe_entry *T_p_entry(int port, int IP, uint64_t token)
{
    struct doca_flow_error error = {0};
    struct doca_flow_match match = {0};
    struct doca_flow_monitor monitor = {0};

    match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
    match.out_dst_ip.ipv4_addr = 0xffffffff;

    printf("\nreal_num = %ld\n", token);

    struct doca_flow_fwd fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port + 1;
    monitor.flags |= DOCA_FLOW_MONITOR_METER;
    monitor.flags |= DOCA_FLOW_MONITOR_COUNT;

    doca_be32_t dst_ip_addr = BE_IPV4_ADDR(192, 168, 201, IP);
    memset(&match, 0, sizeof(match));
    match.out_dst_ip.ipv4_addr = dst_ip_addr;

    monitor.cir = token;
    monitor.cbs = 150000000;

    entry1[port] = doca_flow_pipe_add_entry(0, F[port], &match, NULL, &monitor, &fwd, 0, NULL, &error);
    if (doca_flow_pipe_entry_get_status(entry1[port]) == DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        printf(" SUCC = %ld\n", token);
    if (!entry1[port])
    {
        DOCA_LOG_ERR("%d %s", port, error.message);
    }
    return entry1[port];
}

/* main processing loop */
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
int l2fwd_process_packets(void *process_pkts_params)
{
    // uint64_t cur_tsc, last_tsc;
    uint64_t diff_ns;
    static uint64_t prev_ns;
    int core_id = rte_lcore_id();
    struct rte_mbuf *mbufs[BURST_SIZE];
    int j, nb_rx, rx_port, tx_port, q_id, recv;
    struct core_conf *params = &core_confs[core_id];
    struct l2fwd_config *app_config = ((struct l2fwd_process_pkts_params *)process_pkts_params)->cfg;
    struct app_vnf *vnf = ((struct l2fwd_process_pkts_params *)process_pkts_params)->vnf;

    rx_port = params->ports[1];
    tx_port = params->ports[0];
    q_id = params->queues[0];

    if (!params->used)
    {
        DOCA_LOG_DBG("core %u nothing need to do", core_id);
        return 0;
    }
    DOCA_LOG_INFO("core %u process queue %u start", core_id, params->queues[0]);
    clock_gettime(CLOCK_MONOTONIC, &P_time);
    clock_gettime(CLOCK_MONOTONIC, &C_time);
    struct doca_flow_query Q[nport];
    struct doca_flow_query Q_p[nport];
    uint64_t diff_bytes_E;
    double speed[nport];
    double P_speed[nport];
    
    // 公平队列

    Node A = {0};
    strcpy(A.name, "A");
    A.children = (Node **)malloc(node_num * sizeof(Node *));
    Node B = {0};
    strcpy(B.name, "B");
    B.children = (Node **)malloc(node_num * sizeof(Node *));
    Node C = {0};
    strcpy(C.name, "C");
    C.children = (Node **)malloc(node_num * sizeof(Node *));
    Node D = {0};
    strcpy(D.name, "D");
    D.children = (Node **)malloc(node_num * sizeof(Node *));
    Node S0 = {0};
    strcpy(S0.name, "S0");
    S0.children = (Node **)malloc(node_num * sizeof(Node *));
    Node S1 = {0};
    strcpy(S1.name, "S1");
    S1.children = (Node **)malloc(node_num * sizeof(Node *));
    Node S2 = {0};
    strcpy(S2.name, "S2");
    S2.children = (Node **)malloc(node_num * sizeof(Node *));

    S0.children[0] = &A;
    S0.children[1] = &B;
    S0.children[2] = &C;
    S0.children[3] = &D;
    A.children[0] = NULL;
    A.children[1] = NULL;
    A.children[2] = NULL;
    A.children[3] = NULL;
    B.children[0] = NULL;
    B.children[1] = NULL;
    B.children[2] = NULL;
    B.children[3] = NULL;
    C.children[0] = NULL;
    C.children[1] = NULL;
    C.children[2] = NULL;
    C.children[3] = NULL;
    D.children[0] = NULL;
    D.children[1] = NULL;
    D.children[2] = NULL;
    D.children[3] = NULL;

    A.set_data = 8 * Token[0] / 1000000;
    B.set_data = 8 * Token[1] / 1000000;
    C.set_data = 8 * Token[2] / 1000000;
    D.set_data = 8 * Token[3] / 1000000;

    while (!force_quit)
    {
        if (core_id == rte_get_main_lcore())
        {
            usleep(1000);
            clock_gettime(CLOCK_MONOTONIC, &C_time);
            if (1)
            {
                uint64_t ns;
                ns = C_time.tv_sec * NS_PER_SEC;
                ns += C_time.tv_nsec;
                if (prev_ns != 0)
                    diff_ns = ns - prev_ns;
                prev_ns = ns;

                if (1)
                {

                    fp0 = popen("ethtool -S pf1hpf |grep vport_tx_bytes |awk '{print $2}'", "r");
                    fp1 = popen("ethtool -S pf1vf0 |grep vport_tx_bytes |awk '{print $2}'", "r");
                    fp2 = popen("ethtool -S pf1vf1 |grep vport_tx_bytes |awk '{print $2}'", "r");
                    fp3 = popen("ethtool -S pf1vf2 |grep vport_tx_bytes |awk '{print $2}'", "r");

                    fgets(data0, sizeof(data0), fp0);
                    nic_byte[0] = atol(data0);

                    fgets(data1, sizeof(data1), fp1);
                    nic_byte[1] = atol(data1);

                    fgets(data2, sizeof(data2), fp2);
                    nic_byte[2] = atol(data2);

                    fgets(data3, sizeof(data3), fp3);
                    nic_byte[3] = atol(data3);

                    if (flag && flag1)

                    {
                        flag = 0;
                        continue;
                    }
                    for (int j = 0; j < nport - 1; j++)
                    {

                        if (doca_flow_query(entry1[j], &Q[j]) < 0)
                        {
                            printf("\n no number \n");
                        }
                        diff_bytes_E = nic_byte[j] - nic_pbyte[j];
                        nic_speed[j] = 1.0 * diff_bytes_E / diff_ns * 8E3;
                        printf("\nport%d byte_speed: %.2f Mbps\n", j, nic_speed[j]);
                        Q_p[j] = Q[j];
                        nic_pbyte[j] = nic_byte[j];
                        speed[j] = nic_speed[j];
                    }
                }

                flag = 0;

                A.now_speed = speed[0];
                B.now_speed = speed[1];
                C.now_speed = speed[2];
                D.now_speed = speed[3];

                preset(&S0);
                borrow(&S0);
                show(&S0);

                token[0] = A.token;
                token[1] = B.token;
                token[2] = C.token;
                token[3] = D.token;
                for (int j = 0; j < nport - 1; j++)
                {
                    if ((abs(P_token[j] - token[j]) > 500) && (abs(P1_token[j] - token[j]) > 700))
                    {
                        flag = 1;
                    }
                }

                if (flag && flag1)
                {
                    printf("change start%d", flag);
                    for (int j = 0; j < nport - 1; j++) // 修改
                    {
                        tem_token = token[j] * 1000000 / 8;
                        doca_flow_pipe_rm_entry(0, NULL, entry1[j]);
                        entry = T_p_entry(j, 2 * j + 1, tem_token);
                        P_speed[j] = speed[j];
                    }
                }
                flag1 = flag;
                flag2 = flag1;
                printf("Timenow=%ld\n", C_time.tv_sec);
                printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
                P_time = C_time;

                P2_token[0] = P1_token[0];
                P2_token[1] = P1_token[1];
                P2_token[2] = P1_token[2];
                P2_token[3] = P1_token[3];

                P1_token[0] = P_token[0];
                P1_token[1] = P_token[1];
                P1_token[2] = P_token[2];
                P1_token[3] = P_token[3];

                P_token[0] = token[0];
                P_token[1] = token[1];
                P_token[2] = token[2];
                P_token[3] = token[3];
            }
        }

        //
        nb_rx = rte_eth_rx_burst(rx_port, q_id, mbufs, BURST_SIZE);
        for (j = 0; j < nb_rx; j++)
        {
            if (core_id == rte_get_main_lcore())
                l2fwd_process_offload(mbufs[j], q_id, vnf);
            if (app_config->rx_only)
                rte_pktmbuf_free(mbufs[j]);
            else
                rte_eth_tx_burst(tx_port, q_id, &mbufs[j], 1);
        }
        recv += nb_rx;
    }

    return 0;
}

static int l2fwd_handle_packet(struct l2fwd_pkt_info *pinfo)
{
    return 0;
}

void l2fwd_map_queue(struct application_port_config *port_cfg)
{
    int i, queue_idx = 0, port_idx = 0;
    int nb_ports = port_cfg->nb_ports;

    memset(core_confs, 0, sizeof(core_confs));
    for (i = 0; i < MAX_LCORE; i++)
    {
        if (!rte_lcore_is_enabled(i))
            continue;
        core_confs[i].ports[0] = port_idx % nb_ports;
        core_confs[i].ports[1] = ++port_idx % nb_ports;
        core_confs[i].queues[0] = queue_idx;
        core_confs[i].queues[1] = queue_idx;
        core_confs[i].used = true;
        queue_idx++;
        if (queue_idx >= port_cfg->nb_queues)
            break;
    }
}

struct doca_flow_pipe *
create_control_pipe(struct doca_flow_port *port, struct doca_flow_error *error)
{
    struct doca_flow_pipe_cfg pipe_cfg;
    struct doca_flow_pipe *control_pipe;

    memset(&pipe_cfg, 0, sizeof(pipe_cfg));

    pipe_cfg.attr.name = "CONTROL_PIPE";
    pipe_cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
    pipe_cfg.port = port;

    control_pipe = doca_flow_pipe_create(&pipe_cfg, NULL, NULL, error);
    if (control_pipe == NULL)
    {
        DOCA_LOG_ERR("Failed to create control pipe - %s (%u)\n", error->message, error->type);
        return NULL;
    }

    return control_pipe;
}

int add_control_single_entry(int port, int IP, struct doca_flow_pipe *control_pipe, struct doca_flow_error *error)
{
    struct doca_flow_match match;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_entry *entry;
    uint8_t priority = 0;
    memset(&match, 0, sizeof(match));
    memset(&fwd, 0, sizeof(fwd));
    match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
    match.out_l4_type = DOCA_PROTO_TCP;
    doca_be32_t dst_ip_addr = BE_IPV4_ADDR(192, 168, 201, IP);
    match.out_dst_ip.ipv4_addr = dst_ip_addr;

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = F[port];

    entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match, NULL, &fwd, error);
    if (entry == NULL)
    {
        DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)\n", error->message, error->type);
        return -1;
    }

    // 修改部分！！！
    priority = 1;
    memset(&match, 0, sizeof(match));
    memset(&fwd, 0, sizeof(fwd));
    match.out_eth_type = (0x0608);
    //	SET_MAC_ADDR(match.out_dst_mac, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    match.in_dst_ip.ipv4_addr = dst_ip_addr;
    match.in_dst_ip.type = DOCA_FLOW_IP4_ADDR;

    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port + 1;
    entry = doca_flow_pipe_control_add_entry(0, priority, control_pipe, &match, NULL, &fwd, error);
    if (entry == NULL)
    {
        DOCA_LOG_ERR("Failed to add control pipe entry - %s (%u)\n", error->message, error->type);
        return -1;
    }
    //

    return 0;
}

int add_control_pipe_entries(struct doca_flow_pipe *control_pipe, struct doca_flow_error *error)
{

    for (int j = 0; j < nport - 1; j++)
    {

        add_control_single_entry(j, 2 * j + 1, control_pipe, error);
    }
    return 0;
}

static void B(int port, int IP, uint64_t token)
{
    struct doca_flow_error error = {0};
    struct doca_flow_match match = {0};
    struct doca_flow_actions actions = {0}, *actions_attr[1];
    struct doca_flow_monitor monitor = {0};
    struct doca_flow_pipe_cfg pipe_cfg = {0};
    pipe_cfg.attr.name = "PRT_FWD";
    pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    pipe_cfg.port = fwd_ports[port + 1];
    pipe_cfg.attr.is_root = true;
    pipe_cfg.match = &match;
    actions_attr[0] = &actions;
    pipe_cfg.actions = actions_attr;
    pipe_cfg.monitor = &monitor;
    // 去除match就能使用iperf测量

    struct doca_flow_fwd fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0;
    FB[port] = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &error);
    if (!FB[port])
    {

        DOCA_LOG_ERR("%s", error.message);
    }
    // doca_be32_t dst_ip_addr_B = BE_IPV4_ADDR(192, 168, 200, IP);
    memset(&match, 0, sizeof(match));
    entry2[port] = doca_flow_pipe_add_entry(0, FB[port], &match, NULL, &monitor, &fwd, 0, NULL, &error);
    if (!entry2[port])
    {
        DOCA_LOG_ERR("%s", error.message);
    }
}

static void T(int port, int IP, uint64_t token)
{
    struct doca_flow_error error = {0};
    struct doca_flow_match match = {0};
    struct doca_flow_actions actions = {0}, *actions_attr[1];
    struct doca_flow_monitor monitor = {0};
    struct doca_flow_pipe_cfg pipe_cfg = {0};
    pipe_cfg.attr.name = "PRT_FWD";
    pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
    pipe_cfg.port = fwd_ports[0];
    pipe_cfg.attr.is_root = false;
    pipe_cfg.match = &match;
    actions_attr[0] = &actions;
    pipe_cfg.actions = actions_attr;
    pipe_cfg.monitor = &monitor;
    // 去除match就能使用iperf测量

    match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
    match.out_dst_ip.ipv4_addr = 0xffffffff;
    struct doca_flow_fwd fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = port + 1;
    monitor.flags |= DOCA_FLOW_MONITOR_METER;
    monitor.flags |= DOCA_FLOW_MONITOR_COUNT;
    F[port] = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &error);
    if (!F[port])
    {
        DOCA_LOG_ERR("%s", error.message);
    }
    doca_be32_t dst_ip_addr = BE_IPV4_ADDR(192, 168, 201, IP);
    memset(&match, 0, sizeof(match));

    match.out_dst_ip.ipv4_addr = dst_ip_addr;

    monitor.cir = token;

    //	monitor.cbs = token;
    monitor.cbs = 1500000000;
    entry1[port] = doca_flow_pipe_add_entry(0, F[port], &match, NULL, &monitor, &fwd, 0, NULL, &error);
    if (!entry1[port])
    {
        DOCA_LOG_ERR("%s", error.message);
    }
}

static int l2fwd_init(struct application_port_config *port_cfg)
{
    int portid;
    struct doca_flow_error error = {0};
    struct doca_flow_port *port;
    struct doca_flow_cfg cfg = {
        .queues = port_cfg->nb_queues,
        // .mode_args = "vnf",
        .mode_args = "switch",
        .resource.nb_meters = nb_meters,
        .resource.nb_counters = nb_counters};

    if (doca_flow_init(&cfg, &error))
    {
        DOCA_LOG_ERR("failed to init doca:%s", error.message);
        return -1;
    }

    /* build doca port */
    for (portid = 0; portid < port_cfg->nb_ports; portid++)
    {
        port = l2fwd_init_doca_port(portid, port_cfg->nb_ports, port_cfg->nb_queues);
        if (port == NULL)
        {
            DOCA_LOG_ERR("failed to start port %d %s",
                         portid, error.message);
            return -1;
        }
    }
    for (int j = 0; j < nport - 1; j++)
    {
        B(j, 2 * j + 1, Token[j]);
    }

    for (int j = 0; j < nport - 1; j++)
    {
        T(j, 2 * j + 1, Token[j]);
    }

    control_pipe = create_control_pipe(fwd_ports[0], &error);
    add_control_pipe_entries(control_pipe, &error);
    return 0;
}

static int l2fwd_destroy(void)
{
    doca_flow_destroy();
    return 0;
}

struct app_vnf l2fwd_vnf = {
    .vnf_init = &l2fwd_init,
    .vnf_process_pkt = &l2fwd_handle_packet,
    .vnf_destroy = &l2fwd_destroy,
};

struct app_vnf *l2fwd_get_vnf(void)
{
    return &l2fwd_vnf;
}

static doca_error_t nr_ports_callback(void *config, void *param)
{
    struct l2fwd_config *app_config = (struct l2fwd_config *)config;

    app_config->dpdk_cfg->port_config.nb_ports = *(int *)param;
    DOCA_LOG_DBG("set nr_ports:%d", app_config->dpdk_cfg->port_config.nb_ports);

    return DOCA_SUCCESS;
}

static doca_error_t nr_queues_callback(void *config, void *param)
{
    struct l2fwd_config *app_config = (struct l2fwd_config *)config;
    int nr_queues = *(int *)param;

    app_config->dpdk_cfg->port_config.nb_queues = nr_queues;
    DOCA_LOG_DBG("set nr_queues:%u", nr_queues);

    return DOCA_SUCCESS;
}

static doca_error_t rx_only_callback(void *config, void *param)
{
    struct l2fwd_config *app_config = (struct l2fwd_config *)config;

    app_config->rx_only = *(bool *)param ? 1 : 0;
    DOCA_LOG_DBG("set rx_only:%u", app_config->rx_only);

    return DOCA_SUCCESS;
}

static doca_error_t nr_hairpin_callback(void *config, void *param)
{
    struct l2fwd_config *app_config = (struct l2fwd_config *)config;
    int nr_hairpin = *(int *)param;

    app_config->dpdk_cfg->port_config.nb_hairpin_q = nr_hairpin;
    DOCA_LOG_DBG("set hairpin_queues:%u", nr_hairpin);

    return DOCA_SUCCESS;
}

void register_l2fwd_params()
{
    doca_error_t ret;
    struct doca_argp_param *nr_ports_param;
    struct doca_argp_param *nr_queues_param;
    struct doca_argp_param *nr_hairpin_param;
    struct doca_argp_param *rx_only_param;

    ret = doca_argp_param_create(&nr_ports_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to create ARGP param: %s", doca_get_error_string(ret));
    doca_argp_param_set_short_name(nr_ports_param, "p");
    doca_argp_param_set_long_name(nr_ports_param, "nr-ports");
    doca_argp_param_set_arguments(nr_ports_param, "<num>");
    doca_argp_param_set_description(nr_ports_param, "Set ports number");
    doca_argp_param_set_callback(nr_ports_param, nr_ports_callback);
    doca_argp_param_set_type(nr_ports_param, DOCA_ARGP_TYPE_INT);
    ret = doca_argp_register_param(nr_ports_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to register program param: %s", doca_get_error_string(ret));

    ret = doca_argp_param_create(&nr_queues_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to create ARGP param: %s", doca_get_error_string(ret));
    doca_argp_param_set_short_name(nr_queues_param, "q");
    doca_argp_param_set_long_name(nr_queues_param, "nr-queues");
    doca_argp_param_set_arguments(nr_queues_param, "<num>");
    doca_argp_param_set_description(nr_queues_param, "Set standard queues number");
    doca_argp_param_set_callback(nr_queues_param, nr_queues_callback);
    doca_argp_param_set_type(nr_queues_param, DOCA_ARGP_TYPE_INT);
    ret = doca_argp_register_param(nr_queues_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to register program param: %s", doca_get_error_string(ret));

    ret = doca_argp_param_create(&nr_hairpin_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to create ARGP param: %s", doca_get_error_string(ret));
    doca_argp_param_set_short_name(nr_hairpin_param, "b");
    doca_argp_param_set_long_name(nr_hairpin_param, "nr-hairpin");
    doca_argp_param_set_arguments(nr_hairpin_param, "<num>");
    doca_argp_param_set_description(nr_hairpin_param, "Set hairpin queues number");
    doca_argp_param_set_callback(nr_hairpin_param, nr_hairpin_callback);
    doca_argp_param_set_type(nr_hairpin_param, DOCA_ARGP_TYPE_INT);
    ret = doca_argp_register_param(nr_hairpin_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to register program param: %s", doca_get_error_string(ret));

    ret = doca_argp_param_create(&rx_only_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to create ARGP param: %s", doca_get_error_string(ret));
    doca_argp_param_set_short_name(rx_only_param, "r");
    doca_argp_param_set_long_name(rx_only_param, "rx-only");
    doca_argp_param_set_description(rx_only_param, "Set rx only");
    doca_argp_param_set_callback(rx_only_param, rx_only_callback);
    doca_argp_param_set_type(rx_only_param, DOCA_ARGP_TYPE_BOOLEAN);
    ret = doca_argp_register_param(rx_only_param);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to register program param: %s", doca_get_error_string(ret));

    ret = doca_argp_register_version_callback(sdk_version_callback);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to register version callback: %s", doca_get_error_string(ret));
}

int main(int argc, char **argv)
{
    doca_error_t ret;
    struct doca_logger_backend *logger;

    struct application_dpdk_config dpdk_config = {
        .port_config.nb_ports = 0,
        .port_config.nb_queues = 0,
        .port_config.nb_hairpin_q = 0,

        .sft_config = {0},
    };

    struct l2fwd_config app_cfg = {
        .dpdk_cfg = &dpdk_config,
        .rx_only = 0,
        .stats_timer = 2,
    };
    struct app_vnf *vnf;
    struct l2fwd_process_pkts_params process_pkts_params = {
        .cfg = &app_cfg};

    /* Parse cmdline/json arguments */

    ret = doca_argp_init("l2fwd", &app_cfg);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to parse application input: %s", doca_get_error_string(ret));

    doca_argp_set_dpdk_program(dpdk_init);
    register_l2fwd_params();

    ret = doca_argp_start(argc, argv);

    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to parse application input: %s", doca_get_error_string(ret));

    ret = doca_log_create_syslog_backend("doca_core", &logger);
    if (ret != DOCA_SUCCESS)
        APP_EXIT("Failed to allocate the logger");

    /* update queues and ports */
    dpdk_queues_and_ports_init(&dpdk_config);

    nport = dpdk_config.port_config.nb_ports;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* convert to number of cycles */
    app_cfg.stats_timer *= rte_get_timer_hz();
    vnf = l2fwd_get_vnf();
    if (vnf->vnf_init(&dpdk_config.port_config) != 0)
    {
        DOCA_LOG_ERR("vnf application init error");
        goto exit_app;
    }
    l2fwd_map_queue(&dpdk_config.port_config);
    process_pkts_params.vnf = vnf;
    rte_eal_mp_remote_launch(l2fwd_process_packets, &process_pkts_params, CALL_MAIN);
    rte_eal_mp_wait_lcore();

exit_app:
    /* cleanup app resources */
    l2fwd_destroy();

    pclose(fp0);
    pclose(fp1);
    pclose(fp2);
    pclose(fp3);

    /* cleanup resources */
    dpdk_queues_and_ports_fini(&dpdk_config);
    dpdk_fini();

    /* ARGP cleanup */
    doca_argp_destroy();

    return 0;
}

