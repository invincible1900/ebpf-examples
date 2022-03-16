// +build ignore

//#include "common.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];	
	u8 filename[128];
	//u64 filename;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	// __uint(max_entries, 1 << 12);
	__uint(max_entries, 64 * 4096);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/security_mmap_file")
int kprobe_smf(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	unsigned long prot;

	struct file *file = NULL;
        struct dentry *dentry = NULL;
        const unsigned char *path = NULL;

#if 0
	prot = ctx->si;
 #define VM_EXEC         0x00000004
         // 过滤掉非可执行文件
         if(!(prot & VM_EXEC))
                 return 0;
#endif
	
	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);

	file = (void *)(ctx->di);
        if(file){
                dentry = BPF_CORE_READ(file, f_path.dentry);
                if(dentry)
                        path = (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);
        		if(path)
                		bpf_probe_read_str(&task_info->filename, sizeof(task_info->filename), (void *)path);	

	}

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
