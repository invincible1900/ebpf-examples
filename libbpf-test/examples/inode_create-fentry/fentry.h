#define MAX_LEN 128

struct event {
	// event data here
	int pid;
	char task_name[MAX_LEN];
	char filename[MAX_LEN];
	char files[128][128];
	unsigned long test;
};

