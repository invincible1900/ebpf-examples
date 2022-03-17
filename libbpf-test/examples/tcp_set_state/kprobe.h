#define TASK_COMM_LEN 16

struct event_t
{
    unsigned long start_ns;   //启动时间
    unsigned long end_ns;
    unsigned int pid;
    unsigned int laddr;
    unsigned short lport;
    unsigned int raddr;
    unsigned short rport;
    unsigned char flags;
    unsigned long rx_b;
    unsigned long tx_b;
    char task[TASK_COMM_LEN];
    unsigned short family;
    unsigned int uid;
} __attribute__((packed));




