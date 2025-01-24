#include "../inc/ft_strace.h"
 // (?<=addr)[^"]+

t_syscall syscalls64[] = {
    {0, "read", 3, {"int", "char *", "unsigned long"}, "long"},
    {1, "write", 3, {"int", "char *", "unsigned long"}, "long"},
    {2, "open", 2, {"char *", "int"}, "int"},
    {3, "close", 1, {"int"}, "int"},
    {4, "stat", 2, {"char *", "addr"}, "int"},
    {5, "fstat", 2, {"int", "addr"}, "int"},
    {6, "lstat", 2, {"char *", "addr"}, "int"},
    {7, "poll", 3, {"addr", "addr", "int"}, "int"},
    {8, "lseek", 3, {"int", "long", "int"}, "long"},
    {9, "mmap", 6, {"void", "unsigned long", "int", "int", "int", "long"}, "void *"},
    {10, "mprotect", 3, {"void", "unsigned long", "int"}, "int"},
    {11, "munmap", 2, {"void", "unsigned long"}, "int"},
    {12, "brk", 1, {"void"}, "int"},
    {13, "rt_sigaction", 3, {"int", "addr", "addr"}, "int"},
    {14, "rt_sigprocmask", 4, {"int", "addr", "addr", "unsigned long"}, "int"},
    {15, "rt_sigreturn", 0, {NULL}, "int"},
    {16, "ioctl", 3, {"int", "unsigned long", "..."}, "int"},
    {17, "pread64", 4, {"int", "char *", "unsigned long", "long"}, "long"},
    {18, "pwrite64", 4, {"int", "char *", "unsigned long", "long"}, "long"},
    {19, "readv", 3, {"int", "char *", "int"}, "long"},
    {20, "writev", 3, {"int", "char *", "int"}, "long"},
    {21, "access", 2, {"char *", "int"}, "int"},
    {22, "pipe", 1, {"int *"}, "int"},
    {23, "select", 5, {"int", "addr", "addr", "addr", "addr"}, "int"},
    {24, "sched_yield", 0, {NULL}, "int"},
    {25, "mremap", 4, {"void", "unsigned long", "unsigned long", "int"}, "void *"},
    {26, "msync", 3, {"void", "unsigned long", "int"}, "int"},
    {27, "mincore", 3, {"void", "unsigned long", "char *"}, "int"},
    {28, "madvise", 3, {"void", "unsigned long", "int"}, "int"},
    {29, "shmget", 3, {"addr", "unsigned long", "int"}, "int"},
    {30, "shmat", 3, {"int", "void", "int"}, "void *"},
    {31, "shmctl", 3, {"int", "int", "addr"}, "int"},
    {32, "dup", 1, {"int"}, "int"},
    {33, "dup2", 2, {"int", "int"}, "int"},
    {34, "pause", 0, {NULL}, "int"},
    {35, "nanosleep", 2, {"addr", "addr"}, "int"},
    {36, "getitimer", 2, {"int", "addr"}, "int"},
    {37, "alarm", 1, {"unsigned int"}, "unsigned int"},
    {38, "setitimer", 3, {"int", "addr", "addr"}, "int"},
    {39, "getpid", 0, {NULL}, "int"},
    {40, "sendfile", 4, {"int", "int", "int *", "unsigned int"}, "long"},
    {41, "socket", 3, {"int", "int", "int"}, "int"},
    {42, "connect", 3, {"int", "addr", "unsigned int"}, "int"},
    {43, "accept", 3, {"int", "addr", "unsigned int"}, "int"},
    {44, "sendto", 6, {"int", "void", "unsigned long", "int", "addr", "unsigned int"}, "long"},
    {45, "recvfrom", 6, {"int", "void", "unsigned long", "int", "addr", "unsigned int"}, "long"},
    {46, "sendmsg", 3, {"int", "addr", "int"}, "long"},
    {47, "recvmsg", 3, {"int", "addr", "int"}, "long"},
    {48, "shutdown", 2, {"int", "int"}, "int"},
    {49, "bind", 3, {"int", "addr", "unsigned int"}, "int"},
    {50, "listen", 2, {"int", "int"}, "int"},
    {51, "getsockname", 3, {"int", "addr", "unsigned int"}, "int"},
    {52, "getpeername", 3, {"int", "addr", "unsigned int"}, "int"},
    {53, "socketpair", 4, {"int", "int", "int", "int"}, "int"},
    {54, "setsockopt", 5, {"int", "int", "int", "void", "unsigned int"}, "int"},
    {55, "getsockopt", 5, {"int", "int", "int", "void", "unsigned int"}, "int"},
    {56, "clone", 1, {"int"}, "int"},
    {57, "fork", 0, {NULL}, "int"},
    {58, "vfork", 0, {NULL}, "int"},
    {59, "execve", 3, {"char *", "char **", "char **"}, "int"},
    {60, "exit", 1, {"int"}, "void"},
    {61, "wait4", 4, {"int", "int *", "int", "addr"}, "int"},
    {62, "kill", 2, {"int", "int"}, "int"},
    {63, "uname", 1, {"addr"}, "int"},
    {64, "semget", 3, {"addr", "int", "int"}, "int"},
    {65, "semop", 3, {"int", "addr", "unsigned long"}, "int"},
    {66, "semctl", 4, {"int", "int", "int", "..."}, "int"},
    {67, "shmdt", 1, {"void"}, "int"},
    {68, "msgget", 2, {"addr", "int"}, "int"},
    {69, "msgsnd", 4, {"int", "void", "unsigned long", "int"}, "int"},
    {70, "msgrcv", 5, {"int", "void", "unsigned long", "long", "int"}, "long"},
    {71, "msgctl", 3, {"int", "int", "addr"}, "int"},
    {72, "fcntl", 3, {"int", "int", "int"}, "int"},
    {73, "flock", 2, {"int", "int"}, "int"},
    {74, "fsync", 1, {"int"}, "int"},
    {75, "fdatasync", 1, {"int"}, "int"},
    {76, "truncate", 2, {"char *", "long"}, "int"},
    {77, "ftruncate", 2, {"int", "long"}, "int"},
    {78, "getdents", 3, {"unsigned int", "addr", "unsigned int"}, "long"},
    {79, "getcwd", 2, {"char *", "unsigned long"}, "char *"},
    {80, "chdir", 1, {"char *"}, "int"},
    {81, "fchdir", 1, {"int"}, "int"},
    {82, "rename", 2, {"char *", "char *"}, "int"},
    {83, "mkdir", 2, {"char *", "unsigned int"}, "int"},
    {84, "rmdir", 1, {"char *"}, "int"},
    {85, "creat", 2, {"char *", "unsigned int"}, "int"},
    {86, "link", 2, {"char *", "char *"}, "int"},
    {87, "unlink", 1, {"char *"}, "int"},
    {88, "symlink", 2, {"char", "char"}, "int"},
    {89, "readlink", 3, {"char *", "char *", "unsigned long"}, "long"},
    {90, "chmod", 2, {"char *", "unsigned int"}, "int"},
    {91, "fchmod", 2, {"int", "unsigned int"}, "int"},
    {92, "chown", 3, {"char *", "unsigned int", "unsigned int"}, "int"},
    {93, "fchown", 3, {"int", "unsigned int", "unsigned int"}, "int"},
    {94, "lchown", 3, {"char *", "unsigned int", "unsigned int"}, "int"},
    {95, "umask", 1, {"unsigned int"}, "unsigned int"},
    {96, "gettimeofday", 2, {"addr", "addr"}, "int"},
    {97, "getrlimit", 2, {"int", "addr"}, "int"},
    {98, "getrusage", 2, {"int", "addr"}, "int"},
    {99, "sysinfo", 1, {"addr"}, "int"},
    {100, "times", 1, {"addr"}, "long"},
    {101, "ptrace", 4, {"int", "int", "void", "void"}, "long"},
    {102, "getuid", 0, {NULL}, "unsigned int"},
    {103, "syslog", 3, {"int", "char *", "int"}, "int"},
    {104, "getgid", 0, {NULL}, "unsigned int"},
    {105, "setuid", 1, {"unsigned int"}, "int"},
    {106, "setgid", 1, {"unsigned int"}, "int"},
    {107, "geteuid", 0, {NULL}, "unsigned int"},
    {108, "getegid", 0, {NULL}, "unsigned int"},
    {109, "setpgid", 2, {"int", "int"}, "int"},
    {110, "getppid", 0, {NULL}, "int"},
    {111, "getpgrp", 0, {NULL}, "int"},
    {112, "setsid", 0, {NULL}, "int"},
    {113, "setreuid", 2, {"unsigned int", "unsigned int"}, "int"},
    {114, "setregid", 2, {"unsigned int", "unsigned int"}, "int"},
    {115, "getgroups", 2, {"int", "unsigned int"}, "int"},
    {116, "setgroups", 2, {"unsigned long", "unsigned int"}, "int"},
    {117, "setresuid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"},
    {118, "getresuid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"},
    {119, "setresgid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"},
    {120, "getresgid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"},
    {121, "getpgid", 1, {"int"}, "int"},
    {122, "setfsuid", 1, {"unsigned int"}, "int"},
    {123, "setfsgid", 1, {"unsigned int"}, "int"},
    {124, "getsid", 1, {"int"}, "int"},
    {125, "capget", 2, {"addr", "cap_user_data_t"}, "int"},
    {126, "capset", 2, {"addr", "cap_user_data_t"}, "int"},
    {127, "rt_sigpending", 1, {"addr"}, "int"},
    {128, "rt_sigtimedwait", 3, {"addr", "addr", "addr"}, "int"},
    {129, "rt_sigqueueinfo", 3, {"int", "int", "addr"}, "int"},
    {130, "rt_sigsuspend", 1, {"addr"}, "int"},
    {131, "sigaltstack", 2, {"stack_t", "stack_t"}, "int"},
    {132, "utime", 2, {"char *", "addr"}, "int"},
    {133, "mknod", 3, {"char *", "unsigned int", "addr"}, "int"},
    {134, "uselib", 1, {"char *"}, "int"},
    {135, "personality", 1, {"unsigned long"}, "int"},
    {136, "ustat", 2, {"addr", "addr"}, "int"},
    {137, "statfs", 2, {"char *", "addr"}, "int"},
    {138, "fstatfs", 2, {"int", "addr"}, "int"},
    {139, "sysfs", 2, {"int", "char *"}, "int"},
    {140, "getpriority", 2, {"int", "unsigned int"}, "int"},
    {141, "setpriority", 3, {"int", "unsigned int", "int"}, "int"},
    {142, "sched_setparam", 2, {"int", "addr"}, "int"},
    {143, "sched_getparam", 2, {"int", "addr"}, "int"},
    {144, "sched_setscheduler", 3, {"int", "int", "addr"}, "int"},
    {145, "sched_getscheduler", 1, {"int"}, "int"},
    {146, "sched_get_priority_max", 1, {"int"}, "int"},
    {147, "sched_get_priority_min", 1, {"int"}, "int"},
    {148, "sched_rr_get_interval", 2, {"int", "addr"}, "int"},
    {149, "mlock", 2, {"void", "unsigned long"}, "int"},
    {150, "munlock", 2, {"void", "unsigned long"}, "int"},
    {151, "mlockall", 1, {"int"}, "int"},
    {152, "munlockall", 0, {NULL}, "int"},
    {153, "vhangup", 0, {NULL}, "int"},
    {154, "modify_ldt", 3, {"int", "void", "unsigned long"}, "int"},
    {155, "pivot_root", 2, {"char *", "char *"}, "int"},
    {156, "_sysctl", 1, {"addr"}, "int"},
    {157, "prctl", 5, {"int", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}, "int"},
    {158, "arch_prctl", 2, {"int", "unsigned long"}, "int"},
    {159, "adjtimex", 1, {"addr"}, "int"},
    {160, "setrlimit", 2, {"int", "addr"}, "int"},
    {161, "chroot", 1, {"char *"}, "int"},
    {162, "sync", 0, {NULL}, "void"},
    {163, "acct", 1, {"char *" }, "int"},
    {164, "settimeofday", 2, {"addr", "addr"}, "int"},
    {165, "mount", 5, {"char *", "char *", "char *", "unsigned long", "void"}, "int"},
    {166, "umount2", 2, {"char *", "int"}, "int"},
    {167, "swapon", 2, {"char *", "int"}, "int"},
    {168, "swapoff", 1, {"char *"}, "int"},
    {169, "reboot", 4, {"int", "int", "int", "void"}, "int"},
    {170, "sethostname", 2, {"char *", "unsigned long"}, "int"},
    {171, "setdomainname", 2, {"char *", "unsigned long"}, "int"},
    {172, "iopl", 1, {"int"}, "int"},
    {173, "ioperm", 3, {"unsigned long", "unsigned long", "int"}, "int"},
    {174, "create_module", 2, {"char *", "unsigned long"}, "unsigned long"},
    {175, "init_module", 3, {"void", "unsigned long", "char *"}, "int"},
    {176, "delete_module", 2, {"char *", "int"}, "int"},
    {177, "get_kernel_syms", 1, {"addr"}, "int"},
    {178, "query_module", 5, {"char *", "int", "void", "unsigned long", "unsigned long"}, "int"},
    {179, "quotactl", 4, {"int", "char *", "int", "unsigned long"}, "int"},
    {180, "nfsservctl", 3, {"int", "addr", "addr"}, "long"},
    {181, "getpmsg", 0, {"unimplemented"}, "unimplemented"},
    {182, "putpmsg", 0, {"unimplemented"}, "unimplemented"},
    {183, "afs_syscall", 0, {"unimplemented"}, "unimplemented"},
    {184, "tuxcall", 0, {"unimplemented"}, "unimplemented"},
    {185, "security", 0, {"unimplemented"}, "unimplemented"},
    {186, "gettid", 0, {NULL}, "int"},
    {187, "readahead", 3, {"int", "unsigned int", "unsigned long"}, "long"},
    {188, "setxattr", 5, {"char *", "char *", "void", "unsigned long", "int"}, "int"},
    {189, "lsetxattr", 5, {"char *", "char *", "void", "unsigned long", "int"}, "int"},
    {190, "fsetxattr", 5, {"int", "char *", "void", "unsigned long", "int"}, "int"},
    {191, "getxattr", 4, {"char *", "char *", "void", "unsigned long"}, "long"},
    {192, "lgetxattr", 4, {"char *", "char *", "void", "unsigned long"}, "long"},
    {193, "fgetxattr", 4, {"int", "char *", "void", "unsigned long"}, "long"},
    {194, "listxattr", 3, {"char *", "char *", "unsigned long"}, "long"},
    {195, "llistxattr", 3, {"char *", "char *", "unsigned long"}, "long"},
    {196, "flistxattr", 3, {"int", "char *", "unsigned long"}, "long"},
    {197, "removexattr", 2, {"char *", "char *"}, "int"},
    {198, "lremovexattr", 2, {"char *", "char *"}, "int"},
    {199, "fremovexattr", 2, {"int", "char *"}, "int"},
    {200, "tkill", 2, {"int", "int"}, "int"},
    {201, "time", 1, {"addr"}, "long"},
    {202, "futex", 6, {"addr", "int", "unsigned int", "addr","addr", "unsigned int"}, "long"},
    {203, "sched_setaffinity", 3, {"int", "unsigned long", "int *"}, "int"},
    {204, "sched_getaffinity", 3, {"int", "unsigned long", "int *"}, "int"},
    {205, "set_thread_area", 1, {"addr"}, "int"},
    {206, "io_setup", 2, {"unsigned", "unsigned int"}, "long"},
    {207, "io_destroy", 1, {"unsigned int"}, "int"},
    {208, "io_getevents", 5, {"unsigned int", "long", "long", "addr", "addr"}, "int"},
    {209, "io_submit", 3, {"unsigned int", "long", "addr"}, "int"},
    {210, "io_cancel", 3, {"unsigned int", "addr", "addr"}, "int"},
    {211, "get_thread_area", 1, {"addr"}, "int"},
    {212, "lookup_dcookie", 3, {"unsigned int", "char *", "unsigned long"}, "int"},
    {213, "epoll_create", 1, {"int"}, "int"},
    {214, "epoll_ctl_old", 4, {"int", "int", "int", "addr"}, "int"},
    {215, "epoll_wait_old", 4, {"int", "addr", "int", "int"}, "int"},
    {216, "remap_file_pages", 5, {"void", "unsigned long", "int", "unsigned long", "int"}, "int"},
    {217, "getdents64", 3, {"int", "void", "unsigned long"}, "long"},
    {218, "set_tid_address", 1, {"int *"}, "int"},
    {219, "restart_syscall", 0, {NULL}, "long"},
    {220, "semtimedop", 4, {"int", "addr", "unsigned long", "addr"}, "int"},
    {221, "fadvise64", 4, {"int", "long", "long", "int"}, "int"},
    {222, "timer_create", 3, {"addr", "addr", "addr"}, "int"},
    {223, "timer_settime", 4, {"addr", "int", "addr", "addr"}, "int"},
    {224, "timer_gettime", 2, {"addr", "addr"}, "int"},
    {225, "timer_getoverrun", 1, {"addr"}, "int"},
    {226, "timer_delete", 1, {"addr"}, "int"},
    {227, "clock_settime", 2, {"addr", "addr"}, "int"},
    {228, "clock_gettime", 2, {"addr", "addr"}, "int"},
    {229, "clock_getres", 2, {"addr", "addr"}, "int"},
    {230, "clock_nanosleep", 4, {"addr", "int", "addr", "addr"}, "int"},
    {231, "exit_group", 1, {"int"}, "void"},
    {232, "epoll_wait", 4, {"int", "addr", "int", "int"}, "int"},
    {233, "epoll_ctl", 4, {"int", "int", "int", "addr"}, "int"},
    {234, "tgkill", 3, {"int", "int", "int"}, "int"},
    {235, "utimes", 2, {"char *", "addr"}, "int"},
    {236, "vserver", 0, {"unimplemented"}, "unimplemented"},
    {237, "mbind", 6, {"void", "unsigned long", "int", "unsigned long", "unsigned long", "unsigned"}, "long"},
    {238, "set_mempolicy", 3, {"int", "int *", "unsigned long"}, "long"},
    {239, "get_mempolicy", 5, {"int *", "int *", "unsigned long", "void", "unsigned long"}, "long"},
    {240, "mq_open", 2, {"char *", "int"}, "mqd_t"},
    {241, "mq_unlink", 1, {"char *"}, "int"},
    {242, "mq_timedsend", 5, {"addr", "char *", "unsigned long", "unsigned int", "addr"}, "int"},
    {243, "mq_timedreceive", 5, {"addr", "char *", "unsigned long", "unsigned int", "addr"}, "long"},
    {244, "mq_notify", 2, {"addr", "addr"}, "int"},
    {245, "mq_getsetattr", 3, {"addr", "addr", "addr"}, "int"},
    {246, "kexec_load", 4, {"unsigned long", "unsigned long", "addr", "unsigned long"}, "long"},
    {247, "waitid", 4, {"idtype_t", "unsigned int", "addr", "int"}, "int"},
    {248, "add_key", 5, {"char *", "char *", "void", "unsigned long", "int"}, "int"},
    {249, "request_key", 4, {"char *", "char *", "char *", "int"}, "int"},
    {250, "keyctl", 2, {"int", "..."}, "long"},
    {251, "ioprio_set", 3, {"int", "int", "int"}, "int"},
    {252, "ioprio_get", 2, {"int", "int"}, "int"},
    {253, "inotify_init", 0, {NULL}, "int"},
    {254, "inotify_add_watch", 3, {"int", "char *", "unsigned int"}, "int"},
    {255, "inotify_rm_watch", 2, {"int", "int"}, "int"},
    {256, "migrate_pages", 4, {"int", "unsigned long", "unsigned long", "unsigned long"}, "long"},
    {257, "openat", 3, {"int", "char", "int"}, "int"},
    {258, "mkdirat", 3, {"int", "char *", "unsigned int"}, "int"},
    {259, "mknodat", 4, {"int", "char", "unsigned int", "addr"}, "int"},
    {260, "fchownat", 5, {"int", "char *", "unsigned int", "unsigned int", "int"}, "int"},
    {261, "futimesat", 3, {"int", "char *", "addr"}, "int"},
    {262, "newfstatat", 4, {"int", "char *", "addr", "int"}, "int"},
    {263, "unlinkat", 3, {"int", "char *", "int"}, "int"},
    {264, "renameat", 4, {"int", "char *", "int", "char *"}, "int"},
    {265, "linkat", 5, {"int", "char *", "int", "char *", "int"}, "int"},
    {266, "symlinkat", 3, {"char *", "int", "char *"}, "int"},
    {267, "readlinkat", 4, {"int", "char *", "char *", "unsigned long"}, "long"},
    {268, "fchmodat", 4, {"int", "char *", "unsigned int", "int"}, "int"},
    {269, "faccessat", 4, {"int", "char *", "int", "int"}, "int"},
    {270, "pselect6", 6, {"int", "addr", "addr", "addr", "addr", "addr"}, "int"},
    {271, "ppoll", 4, {"addr", "addr", "addr", "addr"}, "int"},
    {272, "unshare", 1, {"int"}, "int"},
    {273, "set_robust_list", 2, {"addr", "unsigned long"}, "long"},
    {274, "get_robust_list", 3, {"int", "addr", "unsigned long"}, "long"},
    {275, "splice", 6, {"int", "long long", "int", "long long", "unsigned long", "unsigned int"}, "long"},
    {276, "tee", 4, {"int", "int", "unsigned long", "unsigned int"}, "long"},
    {277, "sync_file_range", 4, {"int", "unsigned int", "unsigned int", "unsigned int"}, "int"},
    {278, "vmsplice", 4, {"int", "addr", "unsigned long", "unsigned int"}, "long"},
    {279, "move_pages", 6, {"int", "unsigned long", "void **", "int", "int", "int"}, "long"},
    {280, "utimensat", 4, {"int", "char", "addr", "int"}, "int"},
    {281, "epoll_pwait", 5, {"int", "addr", "int", "int", "addr"}, "int"},
    {282, "signalfd", 3, {"int", "addr", "int"}, "int"},
    {283, "timerfd_create", 2, {"int", "int"}, "int"},
    {284, "eventfd", 2, {"unsigned int", "int"}, "int"},
    {285, "fallocate", 4, {"int", "int", "long", "long"}, "int"},
    {286, "timerfd_settime", 4, {"int", "int", "addr", "addr"}, "int"},
    {287, "timerfd_gettime", 2, {"int", "addr"}, "int"},
    {288, "accept4", 4, {"int", "addr", "unsigned int", "int"}, "int"},
    {289, "signalfd4", 4, {"int", "addr", "unsigned long", "int"}, "int"},
    {290, "eventfd2", 2, {"unsigned int", "int"}, "int"},
    {291, "epoll_create1", 1, {"int"}, "int"},
    {292, "dup3", 3, {"int", "int", "int"}, "int"},
    {293, "pipe2", 2, {"int *", "int"}, "int"},
    {294, "inotify_init1", 1, {"int"}, "int"},
    {295, "preadv", 4, {"int", "char *", "int", "long"}, "long"},
    {296, "pwritev", 4, {"int", "char *", "int", "long"}, "long"},
    {297, "rt_tgsigqueueinfo", 4, {"int", "int", "int", "addr"}, "int"},
    {298, "perf_event_open", 5, {"addr", "int", "int", "int", "unsigned long"}, "int"},
    {299, "recvmmsg", 5, {"int", "addr", "unsigned int", "int", "addr"}, "int"},
    {300, "fanotify_init", 2, {"unsigned int", "unsigned int"}, "int"},
    {301, "fanotify_mark", 5, {"int", "unsigned int", "unsigned long", "int", "char *"}, "int"},
    {302, "prlimit64", 4, {"int", "int", "addr", "addr"}, "int"},
    {303, "name_to_handle_at", 5, {"int", "char *", "addr", "int", "int"}, "int"},
    {304, "open_by_handle_at", 3, {"int", "addr", "int"}, "int"},
    {305, "clock_adjtime", 2, {"addr", "addr"}, "int"},
    {306, "syncfs", 1, {"int"}, "int"},
    {307, "sendmmsg", 4, {"int", "addr", "unsigned int", "int"}, "int"},
    {308, "setns", 2, {"int", "int"}, "int"},
    {309, "getcpu", 3, {"int *", "int *", "addr"}, "int"},
    {310, "process_vm_readv", 6, {"int", "addr", "unsigned long", "addr", "unsigned long", "unsigned long"}, "long"},
    {311, "process_vm_writev", 6, {"int", "addr", "unsigned long", "addr", "unsigned long", "unsigned long"}, "long"},
    {312, "kcmp", 5, {"int", "int", "int", "unsigned long", "unsigned long"}, "int"},
    {313, "finit_module", 3, {"int", "char *", "int"}, "int"},
    {314, "sched_setattr", 3, {"int", "addr", "unsigned int"}, "int"},
    {315, "sched_getattr", 4, {"int", "addr", "unsigned int", "unsigned int"}, "int"},
    {316, "renameat2", 5, {"int", "char *", "int", "char *", "unsigned int"}, "int"},
    {317, "seccomp", 3, {"unsigned int", "unsigned int", "void"}, "int"},
    {318, "getrandom", 3, {"void", "unsigned long", "unsigned int"}, "long"},
    {319, "memfd_create", 2, {"char *", "unsigned int"}, "int"},
    {320, "kexec_file_load", 5, {"int", "int", "unsigned long", "char *", "unsigned long"}, "long"},
    {321, "bpf", 3, {"int", "union bpf_attr", "unsigned int"}, "int"},
    {322, "execveat", 5, {"int", "char *", "char **", "char **", "int"}, "int"},
    {323, "userfaultfd", 1, {"int"}, "int"},
    {324, "membarrier", 3, {"int", "unsigned int", "int"}, "int"},
    {325, "mlock2", 3, {"void", "unsigned long", "int"}, "int"},
    {326, "copy_file_range", 6, {"int", "long long", "int", "long long", "unsigned long", "unsigned int"}, "long"},
    {327, "preadv2", 5, {"int", "char *", "int", "long", "int"}, "long"},
    {328, "pwritev2", 5, {"int", "char *", "int", "long", "int"}, "long"},
    {329, "pkey_mprotect", 4, {"void", "unsigned long", "int", "int"}, "int"},
    {330, "pkey_alloc", 2, {"unsigned int", "unsigned int"}, "int"},
    {331, "pkey_free", 1, {"int"}, "int"},
    {332, "statx", 5, {"int", "char *", "int", "unsigned int", "addr"}, "int"},
    {333, "io_pgetevents", 5, {"unsigned int", "unsigned int", "addr", "addr", "addr"}, "int"},
    {334, "rseq", 4, {"addr", "unsigned int", "unsigned int", "unsigned int"}, "int"},
    {424, "pidfd_send_signal", 4, {"int", "int", "addr", "unsigned int"}, "int"},
    {425, "io_uring_setup", 2, {"unsigned int", "addr"}, "int"},
    {426, "io_uring_enter", 6, {"unsigned int", "unsigned int", "unsigned int", "unsigned int", "addr", "unsigned int"}, "int"},
    {427, "io_uring_register", 4, {"unsigned int", "unsigned int", "addr", "unsigned int"}, "int"},
    {428, "open_tree", 3, {"int", "addr", "unsigned int"}, "int"},
    {429, "move_mount", 5, {"int", "addr", "int", "addr", "unsigned int"}, "int"},
    {430, "fsopen", 2, {"addr", "unsigned int"}, "int"},
    {431, "fsconfig", 5, {"int", "unsigned int", "addr", "addr", "int"}, "int"},
    {432, "fsmount", 5, {"int", "unsigned int", "unsigned int", "addr", "unsigned int"}, "int"},
    {433, "fspick", 3, {"int", "addr", "unsigned int"}, "int"},
    {434, "pidfd_open", 2, {"int", "unsigned int"}, "int"},
    {435, "clone3", 2, {"addr", "unsigned long"}, "long"},
    {436, "close_range", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"},
    {437, "openat2", 4, {"int", "char *", "addr", "unsigned long"}, "long"},
    {438, "pidfd_getfd", 3, {"int", "int", "unsigned int"}, "int"},
    {439, "faccessat2", 4, {"int", "char *", "int", "int"}, "int"},
    {440, "process_madvise", 5, {"int", "addr", "unsigned long", "int", "unsigned int"}, "int"},
    {441, "epoll_pwait2", 6, {"int", "addr", "int", "int", "addr", "unsigned int"}, "int"},
    {442, "mount_setattr", 4, {"int", "addr", "unsigned int", "addr"}, "int"},
    {443, "quotactl_fd", 2, {"unsigned int", "addr"}, "int"},
    {444, "landlock_create_ruleset", 3, {"addr", "unsigned int", "unsigned int"}, "int"},
    {445, "landlock_add_rule", 3, {"int", "addr", "unsigned int"}, "int"},
    {446, "landlock_restrict_self", 2, {"unsigned int", "addr"}, "int"},
    {447, "memfd_secret", 1, {"unsigned int"}, "int"},
    {448, "process_mrelease", 1, {"int"}, "int"},
    {449, NULL, 0, {NULL}, NULL}
};