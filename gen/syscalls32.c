t_syscall syscalls[] = {
    {0, {"restart_syscall", 0, {NULL}, "long"}},
    {1, {"exit", 1, {"int"}, "void"}},
    {2, {"fork", 0, {NULL}, "int"}},
    {3, {"read", 3, {"int", "void", "unsigned long"}, "long"}},
    {4, {"write", 3, {"int", "void", "unsigned long"}, "long"}},
    {5, {"open", 2, {"char", "int"}, "int"}},
    {6, {"close", 1, {"int"}, "int"}},
    {7, {"waitpid", 3, {"int", "int", "int"}, "int"}},
    {8, {"creat", 2, {"char", "unsigned int"}, "int"}},
    {9, {"link", 2, {"char", "char"}, "int"}},
    {10, {"unlink", 1, {"char"}, "int"}},
    {11, {"execve", 3, {"char", "char *", "char *"}, "int"}},
    {12, {"chdir", 1, {"char"}, "int"}},
    {13, {"time", 1, {"time_t"}, "time_t"}},
    {14, {"mknod", 3, {"char", "unsigned int", "addr"}, "int"}},
    {15, {"chmod", 2, {"char", "unsigned int"}, "int"}},
    {16, {"lchown", 3, {"char", "unsigned int", "unsigned int"}, "int"}},
    {17, {"break", 1, {"addr"}, "int"}} ,
    {18, {"oldstat", 2, {"addr", "addr"}, "int"}} ,
    {19, {"lseek", 3, {"int", "long", "int"}, "long"}},
    {20, {"getpid", 0, {NULL}, "int"}},
    {21, {"mount", 5, {"char", "char", "char", "unsigned long", "void"}, "int"}},
    {22, {"umount", 1, {"char"}, "int"}},
    {23, {"setuid", 1, {"unsigned int"}, "int"}},
    {24, {"getuid", 0, {NULL}, "unsigned int"}},
    {25, {"stime", 1, {"time_t"}, "int"}},
    {26, {"ptrace", 4, {"enum __ptrace_request", "int", "void", "void"}, "long"}},
    {27, {"alarm", 1, {"unsigned int"}, "unsigned int"}},
    {28, {"oldfstat", 2, {"int", "addr"}, "int"}} ,
    {29, {"pause", 0, {NULL}, "int"}},
    {30, {"utime", 2, {"char", "addr utimbuf"}, "int"}},
    {31, {"stty", 2, {"int", "addr"}, "int"}} ,
    {32, {"gtty", 2, {"int", "addr"}, "int"}} ,
    {33, {"access", 2, {"char", "int"}, "int"}},
    {34, {"nice", 1, {"int"}, "int"}},
    {35, {"ftime", 1, {"addr"}, "int"}} ,
    {36, {"sync", 0, {NULL}, "void"}},
    {37, {"kill", 2, {"int", "int"}, "int"}},
    {38, {"rename", 2, {"char", "char"}, "int"}},
    {39, {"mkdir", 2, {"char", "unsigned int"}, "int"}},
    {40, {"rmdir", 1, {"char"}, "int"}},
    {41, {"dup", 1, {"int"}, "int"}},
    {42, {"pipe", 0, {NULL}, "addr fd_pair"}},
    {43, {"times", 1, {"addr tms"}, "clock_t"}},
    {44, {"prof", 4, {"addr", "unsigned int", "unsigned int", "unsigned int"}, "int"}} ,
    {45, {"brk", 1, {"void"}, "int"}},
    {46, {"setgid", 1, {"unsigned int"}, "int"}},
    {47, {"getgid", 0, {NULL}, "unsigned int"}},
    {48, {"signal", 2, {"int", "addr"}, "addr"}},
    {49, {"geteuid", 0, {NULL}, "unsigned int"}},
    {50, {"getegid", 0, {NULL}, "unsigned int"}},
    {51, {"acct", 1, {"char"}, "int"}},
    {52, {"umount2", 2, {"char", "int"}, "int"}},
    {53, {"lock", 1, {"int"}, "int"}} ,
    {54, {"ioctl", 3, {"int", "unsigned long", "..."}, "int"}},
    {55, {"fcntl", 3, {"int", "int", "int"}, "int"}},
    {56, {"mpx", 0, {"unimplemented"}, "unimplemented"}} ,
    {57, {"setpgid", 2, {"int", "int"}, "int"}},
    {58, {"ulimit", 2, {"int", "long"}, "long"}},
    {59, {"oldolduname", 1, {"addr"}, "int"}},
    {60, {"umask", 1, {"unsigned int"}, "unsigned int"}},
    {61, {"chroot", 1, {"char"}, "int"}},
    {62, {"ustat", 2, {"addr", "addr ustat"}, "int"}},
    {63, {"dup2", 2, {"int", "int"}, "int"}},
    {64, {"getppid", 0, {NULL}, "int"}},
    {65, {"getpgrp", 0, {NULL}, "int"}},
    {66, {"setsid", 0, {NULL}, "int"}},
    {67, {"sigaction", 3, {"int", "addr sigaction", "addr sigaction"}, "int"}},
    {68, {"sgetmask", 0, {NULL}, "long"}},
    {69, {"ssetmask", 1, {"long"}, "long"}},
    {70, {"setreuid", 2, {"unsigned int", "unsigned int"}, "int"}},
    {71, {"setregid", 2, {"unsigned int", "unsigned int"}, "int"}},
    {72, {"sigsuspend", 1, {"addr"}, "int"}},
    {73, {"sigpending", 1, {"addr"}, "int"}},
    {74, {"sethostname", 2, {"char", "unsigned long"}, "int"}},
    {75, {"setrlimit", 2, {"int", "addr rlimit"}, "int"}},
    {76, {"getrlimit", 2, {"int", "addr rlimit"}, "int"}},
    {77, {"getrusage", 2, {"int", "addr rusage"}, "int"}},
    {78, {"gettimeofday", 2, {"addr timeval", "addr timezone"}, "int"}},
    {79, {"settimeofday", 2, {"addr timeval", "addr timezone"}, "int"}},
    {80, {"getgroups", 2, {"int", "unsigned int"}, "int"}},
    {81, {"setgroups", 2, {"unsigned long", "unsigned int"}, "int"}},
    {82, {"select", 5, {"int", "addr", "addr", "addr", "addr timeval"}, "int"}},
    {83, {"symlink", 2, {"char", "char"}, "int"}},
    {84, {"oldlstat", 2, {"addr", "addr"}, "int"}},
    {85, {"readlink", 3, {"char", "char", "unsigned long"}, "long"}},
    {86, {"uselib", 1, {"char"}, "int"}},
    {87, {"swapon", 2, {"char", "int"}, "int"}},
    {88, {"reboot", 4, {"int", "int", "int", "void"}, "int"}},
    {89, {"readdir", 3, {"unsigned int", "addr old_linux_dirent", "unsigned int"}, "int"}},
    {90, {"mmap", 6, {"void", "unsigned long", "int", "int", "int", "long"}, "void *"}},
    {91, {"munmap", 2, {"void", "unsigned long"}, "int"}},
    {92, {"truncate", 2, {"char", "long"}, "int"}},
    {93, {"ftruncate", 2, {"int", "long"}, "int"}},
    {94, {"fchmod", 2, {"int", "unsigned int"}, "int"}},
    {95, {"fchown", 3, {"int", "unsigned int", "unsigned int"}, "int"}},
    {96, {"getpriority", 2, {"int", "unsigned int"}, "int"}},
    {97, {"setpriority", 3, {"int", "unsigned int", "int"}, "int"}},
    {98, {"profil", 4, {"addr", "unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {99, {"statfs", 2, {"char", "addr statfs"}, "int"}},
    {100, {"fstatfs", 2, {"int", "addr statfs"}, "int"}},
    {101, {"ioperm", 3, {"unsigned long", "unsigned long", "int"}, "int"}},
    {102, {"socketcall", 2, {"int", "unsigned long"}, "int"}},
    {103, {"syslog", 3, {"int", "char", "int"}, "int"}},
    {104, {"setitimer", 3, {"int", "addr itimerval", "addr itimerval"}, "int"}},
    {105, {"getitimer", 2, {"int", "addr itimerval"}, "int"}},
    {106, {"stat", 2, {"char", "addr stat"}, "int"}},
    {107, {"lstat", 2, {"char", "addr stat"}, "int"}},
    {108, {"fstat", 2, {"int", "addr stat"}, "int"}},
    {109, {"oldolduname", 1, {"addr"}, "int"}},
    {110, {"iopl", 1, {"int"}, "int"}},
    {111, {"vhangup", 0, {NULL}, "int"}},
    {112, {"idle", 0, {NULL}, "int"}},
    {113, {"vm86old", 1, {"addr vm86_struct"}, "int"}},
    {114, {"wait4", 4, {"int", "int", "int", "addr rusage"}, "int"}},
    {115, {"swapoff", 1, {"char"}, "int"}},
    {116, {"sysinfo", 1, {"addr sysinfo"}, "int"}},
    {117, {"ipc", 6, {"unsigned int", "int", "int", "int", "void", "long"}, "int"}},
    {118, {"fsync", 1, {"int"}, "int"}},
    {119, {"sigreturn", 1, {"..."}, "int"}},
    {120, {"clone", 1, {"int"}, "int"}},
    {121, {"setdomainname", 2, {"char", "unsigned long"}, "int"}},
    {122, {"uname", 1, {"addr utsname"}, "int"}},
    {123, {"modify_ldt", 3, {"int", "void", "unsigned long"}, "int"}},
    {124, {"adjtimex", 1, {"addr timex"}, "int"}},
    {125, {"mprotect", 3, {"void", "unsigned long", "int"}, "int"}},
    {126, {"sigprocmask", 3, {"int", "addr", "addr"}, "int"}},
    {127, {"create_module", 2, {"char", "unsigned long"}, "unsigned long"}},
    {128, {"init_module", 3, {"void", "unsigned long", "char"}, "int"}},
    {129, {"delete_module", 2, {"char", "int"}, "int"}},
    {130, {"get_kernel_syms", 1, {"addr kernel_sym"}, "int"}},
    {131, {"quotactl", 4, {"int", "char", "int", "unsigned long"}, "int"}},
    {132, {"getpgid", 1, {"int"}, "int"}},
    {133, {"fchdir", 1, {"int"}, "int"}},
    {134, {"bdflush", 2, {"int", "long"}, "int"}},
    {135, {"sysfs", 2, {"int", "char"}, "int"}},
    {136, {"personality", 1, {"unsigned long"}, "int"}},
    {137, {"afs_syscall", 5, {"long", "long", "long", "long", "long"}, "int"}},
    {138, {"setfsuid", 1, {"unsigned int"}, "int"}},
    {139, {"setfsgid", 1, {"unsigned int"}, "int"}},
    {140, {"_llseek", 5, {"unsigned int", "unsigned long", "unsigned long", "long long", "unsigned int"}, "int"}},
    {141, {"getdents", 3, {"unsigned int", "addr linux_dirent", "unsigned int"}, "long"}},
    {142, {"_newselect", 5, {"int", "addr", "addr", "addr", "addr"}, "int"}},
    {143, {"flock", 2, {"int", "int"}, "int"}},
    {144, {"msync", 3, {"void", "unsigned long", "int"}, "int"}},
    {145, {"readv", 3, {"int", "addr iovec", "int"}, "long"}},
    {146, {"writev", 3, {"int", "addr iovec", "int"}, "long"}},
    {147, {"getsid", 1, {"int"}, "int"}},
    {148, {"fdatasync", 1, {"int"}, "int"}},
    {149, {"_sysctl", 1, {"addr __sysctl_args"}, "int"}},
    {150, {"mlock", 2, {"void", "unsigned long"}, "int"}},
    {151, {"munlock", 2, {"void", "unsigned long"}, "int"}},
    {152, {"mlockall", 1, {"int"}, "int"}},
    {153, {"munlockall", 0, {NULL}, "int"}},
    {154, {"sched_setparam", 2, {"int", "addr sched_param"}, "int"}},
    {155, {"sched_getparam", 2, {"int", "addr sched_param"}, "int"}},
    {156, {"sched_setscheduler", 3, {"int", "int", "addr sched_param"}, "int"}},
    {157, {"sched_getscheduler", 1, {"int"}, "int"}},
    {158, {"sched_yield", 0, {NULL}, "int"}},
    {159, {"sched_get_priority_max", 1, {"int"}, "int"}},
    {160, {"sched_get_priority_min", 1, {"int"}, "int"}},
    {161, {"sched_rr_get_interval", 2, {"int", "addr timespec"}, "int"}},
    {162, {"nanosleep", 2, {"addr timespec", "addr timespec"}, "int"}},
    {163, {"mremap", 4, {"void", "unsigned long", "unsigned long", "int"}, "void *"}},
    {164, {"setresuid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {165, {"getresuid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {166, {"vm86", 2, {"unsigned long", "addr vm86plus_struct"}, "int"}},
    {167, {"query_module", 5, {"char", "int", "void", "unsigned long", "unsigned long"}, "int"}},
    {168, {"poll", 3, {"addr pollfd", "addr", "int"}, "int"}},
    {169, {"nfsservctl", 3, {"int", "addr nfsctl_arg", "union nfsctl_res"}, "long"}},
    {170, {"setresgid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {171, {"getresgid", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {172, {"prctl", 5, {"int", "unsigned long", "unsigned long", "unsigned long", "unsigned long"}, "int"}},
    {173, {"rt_sigreturn", 0, {NULL}, "int"}},
    {174, {"rt_sigaction", 4, {"int", "addr", "addr", "unsigned long"}, "int"}},
    {175, {"rt_sigprocmask", 4, {"int", "addr", "addr", "unsigned long"}, "int"}},
    {176, {"rt_sigpending", 2, {"addr", "unsigned long"}, "int"}},
    {177, {"rt_sigtimedwait", 3, {"addr", "addr", "addr"}, "int"}},
    {178, {"rt_sigqueueinfo", 3, {"int", "int", "addr"}, "int"}},
    {179, {"rt_sigsuspend", 2, {"addr", "unsigned long"}, "int"}},
    {180, {"pread64", 4, {"int", "addr", "unsigned long", "long"}, "long"}},
    {181, {"pwrite64", 4, {"int", "addr", "unsigned long", "long"}, "long"}},
    {182, {"chown", 3, {"char", "unsigned int", "unsigned int"}, "int"}},
    {183, {"getcwd", 2, {"char", "unsigned long"}, "char *"}},
    {184, {"capget", 2, {"addr", "cap_user_data_t"}, "int"}},
    {185, {"capset", 2, {"addr", "cap_user_data_t"}, "int"}},
    {186, {"sigaltstack", 2, {"stack_t", "stack_t"}, "int"}},
    {187, {"sendfile", 4, {"int", "int", "long", "unsigned long"}, "long"}},
    {188, {"getpmsg", 0, {"unimplemented"}, "unimplemented"}},
    {189, {"putpmsg", 0, {"unimplemented"}, "unimplemented"}},
    {190, {"vfork", 0, {NULL}, "int"}},
    {191, {"ugetrlimit", 2, {"int", "addr"}, "int"}},
    {192, {"mmap2", 6, {"void", "unsigned long", "int", "int", "int", "long"}, "void *"}},
    {193, {"truncate64", 2, {"addr", "long"}, "int"}},
    {194, {"ftruncate64", 2, {"int", "long"}, "int"}},
    {195, {"stat64", 2, {"addr", "addr"}, "int"}},
    {196, {"lstat64", 2, {"addr", "addr"}, "int"}},
    {197, {"fstat64", 2, {"int", "addr"}, "int"}},
    {198, {"lchown32", 3, {"addr", "unsigned int", "unsigned int"}, "int"}},
    {199, {"getuid32", 0, {NULL}, "unsigned int"}},
    {200, {"getgid32", 0, {NULL}, "unsigned int"}},
    {201, {"geteuid32", 0, {NULL}, "unsigned int"}},
    {202, {"getegid32", 0, {NULL}, "unsigned int"}},
    {203, {"setreuid32", 2, {"unsigned int", "unsigned int"}, "int"}},
    {204, {"setregid32", 2, {"unsigned int", "unsigned int"}, "int"}},
    {205, {"getgroups32", 2, {"int", "addr"}, "int"}},
    {206, {"setgroups32", 2, {"unsigned int", "addr"}, "int"}},
    {207, {"fchown32", 3, {"int", "unsigned int", "unsigned int"}, "int"}},
    {208, {"setresuid32", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {209, {"getresuid32", 3, {"addr", "addr", "addr"}, "int"}},
    {210, {"setresgid32", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {211, {"getresgid32", 3, {"addr", "addr", "addr"}, "int"}},
    {212, {"chown32", 3, {"addr", "unsigned int", "unsigned int"}, "int"}},
    {213, {"setuid32", 1, {"unsigned int"}, "int"}},
    {214, {"setgid32", 1, {"unsigned int"}, "int"}},
    {215, {"setfsuid32", 1, {"unsigned int"}, "int"}},
    {216, {"setfsgid32", 1, {"unsigned int"}, "int"}},
    {217, {"pivot_root", 2, {"char", "char"}, "int"}},
    {218, {"mincore", 3, {"void", "unsigned long", "unsigned char"}, "int"}},
    {219, {"madvise", 3, {"void", "unsigned long", "int"}, "int"}},
    {220, {"getdents64", 3, {"int", "void", "unsigned long"}, "long"}},
    {221, {"fcntl64", 3, {"int", "int", "addr"}, "int"}},
    {224, {"gettid", 0, {NULL}, "int"}},
    {225, {"readahead", 3, {"int", "unsigned int", "unsigned long"}, "long"}},
    {226, {"setxattr", 5, {"char", "char", "void", "unsigned long", "int"}, "int"}},
    {227, {"lsetxattr", 5, {"char", "char", "void", "unsigned long", "int"}, "int"}},
    {228, {"fsetxattr", 5, {"int", "char", "void", "unsigned long", "int"}, "int"}},
    {229, {"getxattr", 4, {"char", "char", "void", "unsigned long"}, "long"}},
    {230, {"lgetxattr", 4, {"char", "char", "void", "unsigned long"}, "long"}},
    {231, {"fgetxattr", 4, {"int", "char", "void", "unsigned long"}, "long"}},
    {232, {"listxattr", 3, {"char", "char", "unsigned long"}, "long"}},
    {233, {"llistxattr", 3, {"char", "char", "unsigned long"}, "long"}},
    {234, {"flistxattr", 3, {"int", "char", "unsigned long"}, "long"}},
    {235, {"removexattr", 2, {"char", "char"}, "int"}},
    {236, {"lremovexattr", 2, {"char", "char"}, "int"}},
    {237, {"fremovexattr", 2, {"int", "char"}, "int"}},
    {238, {"tkill", 2, {"int", "int"}, "int"}},
    {239, {"sendfile64", 4, {"int", "int", "addr", "unsigned long"}, "long"}},
    {240, {"futex", 6, {"addr", "int", "unsigned int", "addr", "addr", "unsigned int"}, "long"}},
    {241, {"sched_setaffinity", 3, {"int", "unsigned long", "int"}, "int"}},
    {242, {"sched_getaffinity", 3, {"int", "unsigned long", "int"}, "int"}},
    {243, {"set_thread_area", 1, {"addr user_desc"}, "int"}},
    {244, {"get_thread_area", 1, {"addr user_desc"}, "int"}},
    {245, {"io_setup", 2, {"unsigned", "unsigned int"}, "long"}},
    {246, {"io_destroy", 1, {"unsigned int"}, "int"}},
    {247, {"io_getevents", 5, {"unsigned int", "long", "long", "addr io_event", "addr timespec"}, "int"}},
    {248, {"io_submit", 3, {"unsigned int", "long", "addr iocb"}, "int"}},
    {249, {"io_cancel", 3, {"unsigned int", "addr iocb", "addr io_event"}, "int"}},
    {250, {"fadvise64", 4, {"int", "long", "long", "int"}, "int"}},
    {252, {"exit_group", 1, {"int"}, "void"}},
    {253, {"lookup_dcookie", 3, {"unsigned int", "char", "unsigned long"}, "int"}},
    {254, {"epoll_create", 1, {"int"}, "int"}},
    {255, {"epoll_ctl", 4, {"int", "int", "int", "addr epoll_event"}, "int"}},
    {256, {"epoll_wait", 4, {"int", "addr epoll_event", "int", "int"}, "int"}},
    {257, {"remap_file_pages", 5, {"void", "unsigned long", "int", "unsigned long", "int"}, "int"}},
    {258, {"set_tid_address", 1, {"int"}, "int"}},
    {259, {"timer_create", 3, {"addr", "addr sigevent", "addr"}, "int"}},
    {260, {"timer_settime", 4, {"addr", "int", "addr itimerspec", "addr itimerspec"}, "int"}},
    {261, {"timer_gettime", 2, {"addr", "addr itimerspec"}, "int"}},
    {262, {"timer_getoverrun", 1, {"addr"}, "int"}},
    {263, {"timer_delete", 1, {"addr"}, "int"}},
    {264, {"clock_settime", 2, {"addr", "addr timespec"}, "int"}},
    {265, {"clock_gettime", 2, {"addr", "addr timespec"}, "int"}},
    {266, {"clock_getres", 2, {"addr", "addr timespec"}, "int"}},
    {267, {"clock_nanosleep", 4, {"addr", "int", "addr timespec", "addr timespec"}, "int"}},
    {268, {"statfs64", 2, {"addr", "addr"}, "int"}},
    {269, {"fstatfs64", 2, {"int", "addr"}, "int"}},
    {270, {"tgkill", 3, {"int", "int", "int"}, "int"}},
    {271, {"utimes", 2, {"char", "addr timeval"}, "int"}},
    {272, {"fadvise64_64", 4, {"int", "long", "long", "int"}, "int"}},
    {273, {"vserver", 0, {"unimplemented"}, "unimplemented"}},
    {274, {"mbind", 6, {"void", "unsigned long", "int", "unsigned long", "unsigned long", "unsigned"}, "long"}},
    {275, {"get_mempolicy", 5, {"int", "unsigned long", "unsigned long", "void", "unsigned long"}, "long"}},
    {276, {"set_mempolicy", 3, {"int", "unsigned long", "unsigned long"}, "long"}},
    {277, {"mq_open", 2, {"char", "int"}, "mqd_t"}},
    {278, {"mq_unlink", 1, {"char"}, "int"}},
    {279, {"mq_timedsend", 5, {"mqd_t", "char", "unsigned long", "unsigned int", "addr timespec"}, "int"}},
    {280, {"mq_timedreceive", 5, {"mqd_t", "char", "unsigned long", "unsigned int", "addr timespec"}, "long"}},
    {281, {"mq_notify", 2, {"mqd_t", "addr sigevent"}, "int"}},
    {282, {"mq_getsetattr", 3, {"mqd_t", "addr mq_attr", "addr mq_attr"}, "int"}},
    {283, {"kexec_load", 4, {"unsigned long", "unsigned long", "addr kexec_segment", "unsigned long"}, "long"}},
    {284, {"waitid", 4, {"idtype_t", "unsigned int", "addr", "int"}, "int"}},
    {286, {"add_key", 5, {"char", "char", "void", "unsigned long", "key_serial_t"}, "key_serial_t"}},
    {287, {"request_key", 4, {"char", "char", "char", "key_serial_t"}, "key_serial_t"}},
    {288, {"keyctl", 2, {"int", "..."}, "long"}},
    {289, {"ioprio_set", 3, {"int", "int", "int"}, "int"}},
    {290, {"ioprio_get", 2, {"int", "int"}, "int"}},
    {291, {"inotify_init", 0, {NULL}, "int"}},
    {292, {"inotify_add_watch", 3, {"int", "char", "unsigned int"}, "int"}},
    {293, {"inotify_rm_watch", 2, {"int", "int"}, "int"}},
    {294, {"migrate_pages", 4, {"int", "unsigned long", "unsigned long", "unsigned long"}, "long"}},
    {295, {"openat", 3, {"int", "char", "int"}, "int"}},
    {296, {"mkdirat", 3, {"int", "char", "unsigned int"}, "int"}},
    {297, {"mknodat", 4, {"int", "char", "unsigned int", "addr"}, "int"}},
    {298, {"fchownat", 5, {"int", "char", "unsigned int", "unsigned int", "int"}, "int"}},
    {299, {"futimesat", 3, {"int", "char", "addr timeval"}, "int"}},
    {300, {"fstatat64", 4, {"int", "addr", "addr", "int"}, "int"}},
    {301, {"unlinkat", 3, {"int", "char", "int"}, "int"}},
    {302, {"renameat", 4, {"int", "char", "int", "char"}, "int"}},
    {303, {"linkat", 5, {"int", "char", "int", "char", "int"}, "int"}},
    {304, {"symlinkat", 3, {"char", "int", "char"}, "int"}},
    {305, {"readlinkat", 4, {"int", "char", "char", "unsigned long"}, "long"}},
    {306, {"fchmodat", 4, {"int", "char", "unsigned int", "int"}, "int"}},
    {307, {"faccessat", 4, {"int", "char", "int", "int"}, "int"}},
    {308, {"pselect6", 6, {"int", "addr", "addr", "addr", "addr", "addr"}, "int"}},
    {309, {"ppoll", 4, {"addr pollfd", "addr", "addr timespec", "addr"}, "int"}},
    {310, {"unshare", 1, {"int"}, "int"}},
    {311, {"set_robust_list", 2, {"addr robust_list_head", "unsigned long"}, "long"}},
    {312, {"get_robust_list", 3, {"int", "addr robust_list_head", "unsigned long"}, "long"}},
    {313, {"splice", 6, {"int", "long long", "int", "long long", "unsigned long", "unsigned int"}, "long"}},
    {314, {"sync_file_range", 4, {"int", "unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {315, {"tee", 4, {"int", "int", "unsigned long", "unsigned int"}, "long"}},
    {316, {"vmsplice", 4, {"int", "addr iovec", "unsigned long", "unsigned int"}, "long"}},
    {317, {"move_pages", 6, {"int", "unsigned long", "void", "int", "int", "int"}, "long"}},
    {318, {"getcpu", 3, {"unsigned", "unsigned", "addr getcpu_cache"}, "int"}},
    {319, {"epoll_pwait", 5, {"int", "addr epoll_event", "int", "int", "addr"}, "int"}},
    {320, {"utimensat", 4, {"int", "char", "addr timespec", "int"}, "int"}},
    {321, {"signalfd", 3, {"int", "addr", "int"}, "int"}},
    {322, {"timerfd_create", 2, {"int", "int"}, "int"}},
    {323, {"eventfd", 2, {"unsigned int", "int"}, "int"}},
    {324, {"fallocate", 4, {"int", "int", "long", "long"}, "int"}},
    {325, {"timerfd_settime", 4, {"int", "int", "addr itimerspec", "addr itimerspec"}, "int"}},
    {326, {"timerfd_gettime", 2, {"int", "addr itimerspec"}, "int"}},
    {327, {"signalfd4", 3, {"int", "addr", "unsigned long", "int"}, "int"}},
    {328, {"eventfd2", 2, {"unsigned int", "int"}, "int"}},
    {329, {"epoll_create1", 1, {"int"}, "int"}},
    {330, {"dup3", 3, {"int", "int", "int"}, "int"}},
    {331, {"pipe2", 2, {"int", "int"}, "int"}},
    {332, {"inotify_init1", 1, {"int"}, "int"}},
    {333, {"preadv", 4, {"int", "addr iovec", "int", "long"}, "long"}},
    {334, {"pwritev", 4, {"int", "addr iovec", "int", "long"}, "long"}},
    {335, {"rt_tgsigqueueinfo", 4, {"int", "int", "int", "addr"}, "int"}},
    {336, {"perf_event_open", 5, {"addr perf_event_attr", "int", "int", "int", "unsigned long"}, "int"}},
    {337, {"recvmmsg", 5, {"int", "addr mmsghdr", "unsigned int", "int", "addr timespec"}, "int"}},
    {338, {"fanotify_init", 2, {"unsigned int", "unsigned int"}, "int"}},
    {339, {"fanotify_mark", 5, {"int", "unsigned int", "unsigned long", "int", "char"}, "int"}},
    {340, {"prlimit64", 4, {"int", "int", "addr", "addr"}, "int"}},
    {341, {"name_to_handle_at", 5, {"int", "char", "addr file_handle", "int", "int"}, "int"}},
    {342, {"open_by_handle_at", 3, {"int", "addr file_handle", "int"}, "int"}},
    {343, {"clock_adjtime", 2, {"addr", "addr timex"}, "int"}},
    {344, {"syncfs", 1, {"int"}, "int"}},
    {345, {"sendmmsg", 4, {"int", "addr mmsghdr", "unsigned int", "int"}, "int"}},
    {346, {"setns", 2, {"int", "int"}, "int"}},
    {347, {"process_vm_readv", 6, {"int", "addr iovec", "unsigned long", "addr iovec", "unsigned long", "unsigned long"}, "long"}},
    {348, {"process_vm_writev", 6, {"int", "addr iovec", "unsigned long", "addr iovec", "unsigned long", "unsigned long"}, "long"}},
    {349, {"kcmp", 5, {"int", "int", "int", "unsigned long", "unsigned long"}, "int"}},
    {350, {"finit_module", 3, {"int", "char", "int"}, "int"}},
    {351, {"sched_setattr", 3, {"int", "addr sched_attr", "unsigned int"}, "int"}},
    {352, {"sched_getattr", 4, {"int", "addr sched_attr", "unsigned int", "unsigned int"}, "int"}},
    {353, {"renameat2", 5, {"int", "char", "int", "char", "unsigned int"}, "int"}},
    {354, {"seccomp", 3, {"unsigned int", "unsigned int", "void"}, "int"}},
    {355, {"getrandom", 3, {"void", "unsigned long", "unsigned int"}, "long"}},
    {356, {"memfd_create", 2, {"char", "unsigned int"}, "int"}},
    {357, {"bpf", 3, {"int", "union bpf_attr", "unsigned int"}, "int"}},
    {358, {"execveat", 5, {"int", "char", "char *", "char *", "int"}, "int"}},
    {359, {"socket", 3, {"int", "int", "int"}, "int"}},
    {360, {"socketpair", 4, {"int", "int", "int", "int"}, "int"}},
    {361, {"bind", 3, {"int", "addr sockaddr", "unsigned int"}, "int"}},
    {362, {"connect", 3, {"int", "addr sockaddr", "unsigned int"}, "int"}},
    {363, {"listen", 2, {"int", "int"}, "int"}},
    {364, {"accept4", 4, {"int", "addr sockaddr", "unsigned int", "int"}, "int"}},
    {365, {"getsockopt", 5, {"int", "int", "int", "void", "unsigned int"}, "int"}},
    {366, {"setsockopt", 5, {"int", "int", "int", "void", "unsigned int"}, "int"}},
    {367, {"getsockname", 3, {"int", "addr sockaddr", "unsigned int"}, "int"}},
    {368, {"getpeername", 3, {"int", "addr sockaddr", "unsigned int"}, "int"}},
    {369, {"sendto", 6, {"int", "void", "unsigned long", "int", "addr sockaddr", "unsigned int"}, "long"}},
    {370, {"sendmsg", 3, {"int", "addr msghdr", "int"}, "long"}},
    {371, {"recvfrom", 6, {"int", "void", "unsigned long", "int", "addr sockaddr", "unsigned int"}, "long"}},
    {372, {"recvmsg", 3, {"int", "addr msghdr", "int"}, "long"}},
    {373, {"shutdown", 2, {"int", "int"}, "int"}},
    {374, {"userfaultfd", 1, {"int"}, "int"}},
    {375, {"membarrier", 3, {"int", "unsigned int", "int"}, "int"}},
    {376, {"mlock2", 3, {"void", "unsigned long", "int"}, "int"}},
    {377, {"copy_file_range", 6, {"int", "long long", "int", "long long", "unsigned long", "unsigned int"}, "long"}},
    {378, {"preadv2", 5, {"int", "addr iovec", "int", "long", "int"}, "long"}},
    {379, {"pwritev2", 5, {"int", "addr iovec", "int", "long", "int"}, "long"}},
    {380, {"pkey_mprotect", 4, {"void", "unsigned long", "int", "int"}, "int"}},
    {381, {"pkey_alloc", 2, {"unsigned int", "unsigned int"}, "int"}},
    {382, {"pkey_free", 1, {"int"}, "int"}},
    {383, {"statx", 5, {"int", "char", "int", "unsigned int", "addr statx"}, "int"}},
    {384, {"arch_prctl", 2, {"int", "unsigned long"}, "int"}},
    {385, {"io_pgetevents", 6, {"addr", "long", "long", "addr", "addr", "addr"}, "int"}},
    {386, {"rseq", 4, {"addr", "unsigned int", "int", "unsigned long"}, "int"}},
    {393, {"semget", 3, {"addr", "int", "int"}, "int"}},
    {394, {"semctl", 4, {"int", "int", "int", "..."}, "int"}},
    {395, {"shmget", 3, {"addr", "unsigned long", "int"}, "int"}},
    {396, {"shmctl", 3, {"int", "int", "addr shmid_ds"}, "int"}},
    {397, {"shmat", 3, {"int", "void", "int"}, "void *"}},
    {398, {"shmdt", 1, {"void"}, "int"}},
    {399, {"msgget", 2, {"addr", "int"}, "int"}},
    {400, {"msgsnd", 4, {"int", "void", "unsigned long", "int"}, "int"}},
    {401, {"msgrcv", 5, {"int", "void", "unsigned long", "long", "int"}, "long"}},
    {402, {"msgctl", 3, {"int", "int", "addr msqid_ds"}, "int"}},
    {403, {"clock_gettime64", 2, {"int", "addr"}, "int"}},
    {404, {"clock_settime64", 2, {"int", "addr"}, "int"}},
    {405, {"clock_adjtime64", 2, {"int", "addr"}, "int"}},
    {406, {"clock_getres_time64", 2, {"int", "addr"}, "int"}},
    {407, {"clock_nanosleep_time64", 4, {"int", "int", "addr", "addr"}, "int"}},
    {408, {"timer_gettime64", 2, {"addr", "addr"}, "int"}},
    {409, {"timer_settime64", 3, {"addr", "int", "addr"}, "int"}},
    {410, {"timerfd_gettime64", 2, {"int", "addr"}, "int"}},
    {411, {"timerfd_settime64", 4, {"int", "int", "addr", "addr"}, "int"}},
    {412, {"utimensat_time64", 4, {"int", "addr", "addr", "int"}, "int"}},
    {413, {"pselect6_time64", 6, {"int", "addr", "addr", "addr", "addr", "addr"}, "int"}},
    {414, {"ppoll_time64", 5, {"addr", "unsigned int", "addr", "addr", "unsigned long"}, "int"}},
    {416, {"io_pgetevents_time64", 6, {"addr", "long", "long", "addr", "addr", "addr"}, "int"}},
    {417, {"recvmmsg_time64", 5, {"int", "addr", "unsigned int", "unsigned int", "addr"}, "int"}},
    {418, {"mq_timedsend_time64", 5, {"addr", "addr", "unsigned long", "unsigned int", "addr"}, "int"}},
    {419, {"mq_timedreceive_time64", 5, {"addr", "addr", "unsigned long", "addr", "addr"}, "long"}},
    {420, {"semtimedop_time64", 4, {"int", "addr", "unsigned int", "addr"}, "int"}},
    {421, {"rt_sigtimedwait_time64", 4, {"addr", "addr", "addr", "unsigned long"}, "int"}},
    {422, {"futex_time64", 6, {"addr", "int", "int", "addr", "addr", "int"}, "int"}},
    {423, {"sched_rr_get_interval_time64", 2, {"int", "addr"}, "int"}},
    {424, {"pidfd_send_signal", 4, {"int", "int", "addr", "unsigned int"}, "int"}},
    {425, {"io_uring_setup", 2, {"unsigned int", "addr"}, "int"}},
    {426, {"io_uring_enter", 6, {"unsigned int", "unsigned int", "unsigned int", "unsigned int", "addr", "unsigned long"}, "int"}},
    {427, {"io_uring_register", 4, {"unsigned int", "unsigned int", "addr", "unsigned int"}, "int"}},
    {428, {"open_tree", 3, {"int", "addr", "unsigned int"}, "int"}},
    {429, {"move_mount", 5, {"int", "addr", "int", "addr", "unsigned int"}, "int"}},
    {430, {"fsopen", 2, {"addr", "unsigned int"}, "int"}},
    {431, {"fsconfig", 5, {"int", "unsigned int", "addr", "addr", "int"}, "int"}},
    {432, {"fsmount", 3, {"int", "unsigned int", "unsigned int"}, "int"}},
    {433, {"fspick", 3, {"int", "addr", "unsigned int"}, "int"}},
    {434, {"pidfd_open", 2, {"int", "unsigned int"}, "int"}},
    {435, {"clone3", 2, {"addr clone_args", "unsigned long"}, "long"}},
    {436, {"close_range", 3, {"unsigned int", "unsigned int", "unsigned int"}, "int"}},
    {437, {"openat2", 4, {"int", "char", "addr open_how", "unsigned long"}, "long"}},
    {438, {"pidfd_getfd", 3, {"int", "int", "unsigned int"}, "int"}},
    {439, {"faccessat2", 4, {"int", "char", "int", "int"}, "int"}},
    {440, {"process_madvise", 4, {"int", "addr", "unsigned long", "int"}, "long"}},
    {441, {"epoll_pwait2", 5, {"int", "addr", "int", "addr", "addr"}, "int"}},
    {442, {"mount_setattr", 4, {"int", "addr", "unsigned int", "addr"}, "int"}},
    {443, {"quotactl_fd", 3, {"unsigned int", "int", "addr"}, "int"}},
    {444, {"landlock_create_ruleset", 3, {"addr", "unsigned long", "unsigned int"}, "int"}},
    {445, {"landlock_add_rule", 4, {"int", "int", "addr", "unsigned int"}, "int"}},
    {446, {"landlock_restrict_self", 2, {"int", "unsigned int"}, "int"}},
    {447, {"memfd_secret", 1, {"unsigned int"}, "int"}},
    {448, {"process_mrelease", 1, {"int"}, "int"}},
    {0, {NULL, 0, {NULL}, NULL}}
};


