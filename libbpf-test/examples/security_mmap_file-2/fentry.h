#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_PATH_LEN MAX_FILENAME_LEN
struct event {
        int pid;
        int ppid;
        char comm[TASK_COMM_LEN];
        // char filename[MAX_FILENAME_LEN];
        char filename[MAX_PATH_LEN];
};

