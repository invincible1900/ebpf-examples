#define MAX_LEN 128
#if 0
#define _KERNEL_CAPABILITY_U32S 2
typedef struct kernel_cap_struct {
        __u32 cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

typedef struct {
        uid_t val;
} kuid_t;

typedef struct {
        gid_t val;
} kgid_t;
#endif

struct credentials {
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
    unsigned securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
};

struct event {
	// event data here
	int pid;
	char task_name[MAX_LEN];
	struct credentials credentials;
};


