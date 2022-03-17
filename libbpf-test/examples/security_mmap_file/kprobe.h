#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
struct event {
        int pid;
        int ppid;
        char comm[TASK_COMM_LEN];
        char filename[MAX_FILENAME_LEN];
};

