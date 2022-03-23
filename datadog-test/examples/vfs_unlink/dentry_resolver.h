#define DR_MAX_TAIL_CALL          30
#define DR_MAX_ITERATION_DEPTH    45
#define DR_MAX_SEGMENT_LENGTH     255

#define DENTRY_INVALID -1
#define DR_KPROBE_DENTRY_RESOLVER_KERN_KEY 3

#define DR_KPROBE     1
#define DR_TRACEPOINT 2

static int (*bpf_tail_call_compat)(void* ctx, void* map, int key) = (void*)BPF_FUNC_tail_call;

struct path_key_t {
    u64 ino;
    u32 mount_id;
    u32 path_id;
};


struct ktimeval {
    long tv_sec;
    long tv_nsec;
};


struct file_metadata_t {
    u32 uid;
    u32 gid;
    u32 nlink;
    u16 mode;
    char padding[2];

    struct ktimeval ctime;
    struct ktimeval mtime;
};

struct file_t {
    struct path_key_t path_key;
    u32 flags;
    u32 padding;
    struct file_metadata_t metadata;
};



struct policy_t {
    char mode;
    char flags;
};


struct path_leaf_t {
  struct path_key_t parent;
  char name[DR_MAX_SEGMENT_LENGTH + 1];
  u16 len;
};

struct dentry_resolver_input_t {
    struct path_key_t key;
    struct dentry *dentry;
    u64 discarder_type;
    int callback;
    int ret;
    int iteration;
};

struct syscall_cache_t {
    struct policy_t policy;
    u64 type;
    u32 discarded;

    struct dentry_resolver_input_t resolver;

    union{
        struct {
            int flags;
            umode_t mode;
            struct dentry *dentry;
            struct file_t file;
        } open;
    };
};

struct inode_discarder_t {
    struct path_key_t path_key;
    u32 is_leaf;
    u32 padding;
};

struct is_discarded_by_inode_t {
    u64 event_type;
    struct inode_discarder_t discarder;
    u64 now;
    u32 tgid;
    u32 activity_dump_state;
};

enum event_type
{
    EVENT_ANY = 0,
    EVENT_FIRST_DISCARDER = 1,
    EVENT_OPEN = EVENT_FIRST_DISCARDER,
    EVENT_MKDIR,
    EVENT_LINK,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_RMDIR,
    EVENT_CHMOD,
    EVENT_CHOWN,
    EVENT_UTIME,
    EVENT_SETXATTR,
    EVENT_REMOVEXATTR,
    EVENT_LAST_DISCARDER = EVENT_REMOVEXATTR,

    EVENT_MOUNT,
    EVENT_UMOUNT,
    EVENT_FORK,
    EVENT_EXEC,
    EVENT_EXIT,
    EVENT_INVALIDATE_DENTRY,
    EVENT_SETUID,
    EVENT_SETGID,
    EVENT_CAPSET,
    EVENT_ARGS_ENVS,
    EVENT_MOUNT_RELEASED,
    EVENT_SELINUX,
    EVENT_BPF,
    EVENT_PTRACE,
    EVENT_MMAP,
    EVENT_MPROTECT,
    EVENT_INIT_MODULE,
    EVENT_DELETE_MODULE,
    EVENT_SIGNAL,
    EVENT_SPLICE,
    EVENT_CGROUP_TRACING,
    EVENT_MAX, // has to be the last one

    //EVENT_ALL = 0xffffffffffffffff // used as a mask for all the events
};

#if 0
struct bpf_map_def SEC("maps/syscalls") syscalls = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct syscall_cache_t),
    .max_entries = 1024,
    // .pinning = 0,
    // .namespace = "",
};
#else
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct syscall_cache_t));
    __uint(max_entries, 1024);
	__uint(pinning, 0);

} syscalls SEC(".maps");
#endif



#if 0
struct container_context_t {
    char container_id[CONTAINER_ID_LEN];
};

struct proc_cache_t {
    struct container_context_t container;
    struct file_t executable;

    u64 exec_timestamp;
    char tty_name[TTY_NAME_LEN];
    char comm[TASK_COMM_LEN];
};



// defined in exec.h
struct proc_cache_t *get_proc_from_cookie(u32 cookie);

struct proc_cache_t * __attribute__((always_inline)) get_proc_cache(u32 tgid) {
    struct proc_cache_t *entry = NULL;

    struct pid_cache_t *pid_entry = (struct pid_cache_t *) bpf_map_lookup_elem(&pid_cache, &tgid);
    if (pid_entry) {
        // Select the cache entry
        u32 cookie = pid_entry->cookie;
        entry = get_proc_from_cookie(cookie);
    }
    return entry;
}

__attribute__((always_inline)) void fill_activity_dump_discarder_state(void *ctx, struct is_discarded_by_inode_t *params) {
    struct proc_cache_t *proc_entry = get_proc_cache(params->tgid);
    if (proc_entry != NULL) {
        // prepare cgroup and comm (for compatibility with old kernels)
        char cgroup[CONTAINER_ID_LEN] = {};
        bpf_probe_read(&cgroup, sizeof(cgroup), proc_entry->container.container_id);
        char comm[TASK_COMM_LEN] = {};
        bpf_probe_read(&comm, sizeof(comm), proc_entry->comm);

        should_trace_new_process(ctx, params->now, params->tgid, cgroup, comm);
    }

    u64 timeout = lookup_or_delete_traced_pid_timeout(params->tgid, params->now);
    if (timeout == 0) {
        params->activity_dump_state = NO_ACTIVITY_DUMP;
        return;
    }

    // is this event type traced ?
    u64 *traced = bpf_map_lookup_elem(&traced_event_types, &params->event_type);
    if (traced == NULL) {
        params->activity_dump_state = NO_ACTIVITY_DUMP;
        return;
    }

    // set IGNORE_DISCARDER_CHECK
    params->activity_dump_state = IGNORE_DISCARDER_CHECK;
}
#endif

#if 0
struct bpf_map_def SEC("maps/pathnames") pathnames = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct path_key_t),
    .value_size = sizeof(struct path_leaf_t),
    .max_entries = 64000,
    // .pinning = 0,
    // .namespace = "",
};

struct bpf_map_def SEC("maps/dentry_resolver_kprobe_callbacks") dentry_resolver_kprobe_callbacks = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = EVENT_MAX,
};

struct bpf_map_def SEC("maps/dentry_resolver_kprobe_progs") dentry_resolver_kprobe_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 4,
};
#else
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(struct path_key_t));
	__uint(value_size, sizeof(struct path_leaf_t));
	__uint(max_entries, 64000);

} pathnames SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, EVENT_MAX);

}dentry_resolver_kprobe_callbacks SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));	
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 4);
} dentry_resolver_kprobe_progs SEC(".maps");


#endif

static struct syscall_cache_t *__attribute__((always_inline)) peek_syscall(u64 type) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *)bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (!type || syscall->type == type) {
        return syscall;
    }
    return NULL;
}


static void __attribute__((always_inline)) write_dentry_inode(struct dentry *dentry, struct inode **d_inode) {
    bpf_probe_read(d_inode, sizeof(d_inode), &dentry->d_inode);
}

static void __attribute__((always_inline)) write_inode_ino(struct inode *inode, u64 *ino) {
    bpf_probe_read(ino, sizeof(inode), &inode->i_ino);
}

static int __attribute__((always_inline)) resolve_dentry_tail_call(void *ctx, struct dentry_resolver_input_t *input) {
    struct path_leaf_t map_value = {};
    struct path_key_t key = input->key;
    struct path_key_t next_key = input->key;
    struct qstr qstr;
    struct dentry *dentry = input->dentry;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    int segment_len = 0;
    struct is_discarded_by_inode_t params = {
        .event_type = input->discarder_type,
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .now = bpf_ktime_get_ns(),
    };
    // check if we should ignore the normal discarder check because of an activity dump
    //fill_activity_dump_discarder_state(ctx, &params);

    if (key.ino == 0 || key.mount_id == 0) {
        return DENTRY_INVALID;
    }

    /*u64 max_discarder_depth;
    LOAD_CONSTANT("max_discarder_depth", max_discarder_depth);*/

#pragma unroll
    for (int i = 0; i < DR_MAX_ITERATION_DEPTH; i++)
    {
        d_parent = NULL;
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        key = next_key;
        if (dentry != d_parent) {
            write_dentry_inode(d_parent, &d_inode);
            write_inode_ino(d_inode, &next_key.ino);
        } else {
            next_key.ino = 0;
            next_key.mount_id = 0;
        }
#if 0
        if (input->discarder_type && i <= 3) {
            params.discarder.path_key.ino = key.ino;
            params.discarder.path_key.mount_id = key.mount_id;
            params.discarder.is_leaf = i == 0;
            if (is_discarded_by_inode(&params)) {
                return DENTRY_DISCARDED;
            }
        }
#endif
        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        segment_len = bpf_probe_read_str(&map_value.name, sizeof(map_value.name), (void *)qstr.name);
        if (segment_len > 0) {
            map_value.len = (u16) segment_len;
        } else {
            map_value.len = 0;
        }

        if (map_value.name[0] == '/' || map_value.name[0] == 0) {
            map_value.name[0] = '/';
            next_key.ino = 0;
            next_key.mount_id = 0;
        }

        map_value.parent = next_key;

        bpf_map_update_elem(&pathnames, &key, &map_value, BPF_ANY);

        dentry = d_parent;
        if (next_key.ino == 0) {
            input->dentry = d_parent;
            input->key = next_key;
            return i + 1;
        }
    }

    if (input->iteration == DR_MAX_TAIL_CALL) {
        map_value.name[0] = 0;
        map_value.parent.mount_id = 0;
        map_value.parent.ino = 0;
        bpf_map_update_elem(&pathnames, &next_key, &map_value, BPF_ANY);
    }

    // prepare for the next iteration
    input->dentry = d_parent;
    input->key = next_key;
    return DR_MAX_ITERATION_DEPTH;
}



#define dentry_resolver_kern(ctx, progs_map, callbacks_map, dentry_resolver_kern_key)                                  \
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);                                                         \
    if (!syscall)                                                                                                      \
        return 0;                                                                                                      \
                                                                                                                       \
    syscall->resolver.iteration++;                                                                                     \
    syscall->resolver.ret = resolve_dentry_tail_call(ctx, &syscall->resolver);                                         \
                                                                                                                       \
    if (syscall->resolver.ret > 0) {                                                                                   \
        if (syscall->resolver.iteration < DR_MAX_TAIL_CALL && syscall->resolver.key.ino != 0) {                        \
            bpf_tail_call_compat(ctx, progs_map, dentry_resolver_kern_key);                                            \
        }                                                                                                              \
                                                                                                                       \
        syscall->resolver.ret += DR_MAX_ITERATION_DEPTH * (syscall->resolver.iteration - 1);                           \
    }                                                                                                                  \
                                                                                                                       \
    if (syscall->resolver.callback >= 0) {                                                                             \
        bpf_tail_call_compat(ctx, callbacks_map, syscall->resolver.callback);                                          \
    }

#if 1
SEC("kprobe/dentry_resolver_kern")
int kprobe_dentry_resolver_kern(struct pt_regs *ctx) {
    dentry_resolver_kern(ctx, &dentry_resolver_kprobe_progs, &dentry_resolver_kprobe_callbacks, DR_KPROBE_DENTRY_RESOLVER_KERN_KEY);
    return 0;
}
#endif

static int __attribute__((always_inline)) resolve_dentry(void *ctx, int dr_type) {
    if (dr_type == DR_KPROBE) {
        bpf_tail_call_compat(ctx, &dentry_resolver_kprobe_progs, DR_KPROBE_DENTRY_RESOLVER_KERN_KEY);
    } 
#if 0
	else if (dr_type == DR_TRACEPOINT) {
        bpf_tail_call_compat(ctx, &dentry_resolver_tracepoint_progs, DR_TRACEPOINT_DENTRY_RESOLVER_KERN_KEY);
    }
#endif
    return 0;
}


