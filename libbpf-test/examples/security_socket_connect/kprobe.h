#define TASK_COMM_LEN 16

struct ipv4_event_t {
    __u64 ts_us;
    __u32 pid;
    __u32 uid;
    __u32 af;
    __u32 laddr;
    __u16 lport;
    __u32 daddr;
    __u16 dport;
    char task[TASK_COMM_LEN];
} __attribute__((packed));


