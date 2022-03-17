typedef struct _process_info_t
{
    int type;
    pid_t child_pid;
    pid_t child_tgid;
    pid_t parent_pid;
    pid_t parent_tgid;

    pid_t grandparent_pid;
    pid_t grandparent_tgid;
    uid_t uid;
    gid_t gid;


    int cwd_level;
    __u32 uts_inum;
    __u64 start_time;
    char comm[16];
    char cmdline[128];
    char filepath[128];
} proc_info_t;

