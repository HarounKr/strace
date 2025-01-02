#include "../inc/ft_strace.h"

// https://syscall.sh/
t_syscall syscalls[] = {
    // 0 arg
    {"getpid", 0, {NULL}},
    {"getppid", 0, {NULL}},
    {"getuid", 0, {NULL}},
    {"geteuid", 0, {NULL}},
    {"getgid", 0, {NULL}},
    {"getegid", 0, {NULL}},
    {"setsid", 0, {NULL}},
    {"sched_yield", 0, {NULL}},
    {"fork", 0, {NULL}},
    {"vfork", 0, {NULL}},
    {"sync", 0, {NULL}},
    {"pause", 0, {NULL}},
    {"gettimeofday", 0, {NULL}},
    {"time", 0, {NULL}},
    {"uname", 0, {NULL}},
    {"sched_getscheduler", 0, {NULL}},
    {"getpgrp", 0, {NULL}},
    {"gettid", 0, {NULL}},
    {"epoll_create", 0, {NULL}},
    {"getrandom", 0, {NULL}},
    {"timerfd_create", 0, {NULL}},
    {"getcpu", 0, {NULL}},
    // 1 arg
    {"exit", 1, {"int"}},
    {"exit_group", 1, {"int"}},
    {"close", 1, {"int"}},
    {"unlink", 1, {"char*"}},
    {"rmdir", 1, {"char*"}},
    {"syncfs", 1, {"int"}},
    {"fsync", 1, {"int"}},
    {"chdir", 1, {"char*"}},
    {"fchdir", 1, {"int"}},
    {"brk", 1, {"void*"}},
    {"setuid", 1, {"unsigned int"}},
    {"setgid", 1, {"unsigned int"}},
    {"reboot", 1, {"int"}},
    {"umask", 1, {"unsigned int"}},
    {"pipe", 1, {"int*"}},
    {"dup", 1, {"int"}},
    {"dup2", 1, {"int"}},
    {"getpriority", 1, {"int"}},
    {"getpgid", 1, {"int"}},
    {"personality", 1, {"unsigned int"}},
    // 2 args
    {"arch_prctl", 2, {"int", "unsigned int"}},
    {"open", 2, {"char*", "int"}},
    {"rename", 2, {"char*", "char*"}},
    {"mkdir", 2, {"char*", "unsigned int"}},
    {"chmod", 2, {"char*", "unsigned int"}},
    {"munmap", 2, {"void*", "unsigned long"}},
    {"fstat", 2, {"int", "struct stat*"}},
    {"readlink", 2, {"char*", "char*"}},
    {"kill", 2, {"int", "int"}},
    {"ftruncate", 2, {"int", "unsigned long"}},
    {"truncate", 2, {"char*", "unsigned long"}},
    {"ioctl", 2, {"int", "unsigned long"}},
    {"access", 2, {"char*", "int"}},
    {"symlink", 2, {"char*", "char*"}},
    {"link", 2, {"char*", "char*"}},
    {"utime", 2, {"char*", "struct utimbuf*"}},
    {"utimes", 2, {"char*", "struct timeval*"}},
    {"stat", 2, {"char*", "struct stat*"}},
    {"lstat", 2, {"char*", "struct stat*"}},
    {"mount", 2, {"char*", "char*"}},
    {"umount2", 2, {"char*", "int"}},
    // 3 args
    {"read", 3, {"int", "char*", "unsigned long"}},
    {"write", 3, {"int", "char*", "unsigned long"}},
    {"lseek", 3, {"int", "long", "int"}},
    {"socket", 3, {"int", "int", "int"}},
    {"bind", 3, {"int", "struct sockaddr*", "unsigned int"}},
    {"connect", 3, {"int", "struct sockaddr*", "unsigned int"}},
    {"accept", 3, {"int", "struct sockaddr*", "unsigned int*"}},
    {"execve", 3, {"char*", "char**", "char**"}},
    {"mprotect", 3, {"void*", "unsigned long", "int"}},
    {"recvfrom", 3, {"int", "void*", "unsigned long"}},
    {"sendto", 3, {"int", "void*", "unsigned long"}},
    {"shutdown", 3, {"int", "int"}},
    {"recvmsg", 3, {"int", "struct msghdr*", "int"}},
    {"sendmsg", 3, {"int", "struct msghdr*", "int"}},
    {"pread64", 3, {"int", "void*", "unsigned long"}},
    {"pwrite64", 3, {"int", "void*", "unsigned long"}},
    {"getpeername", 3, {"int", "struct sockaddr*", "unsigned int*"}},
    {"getsockname", 3, {"int", "struct sockaddr*", "unsigned int*"}},
    {"getsockopt", 3, {"int", "int", "int"}},
    {"setsockopt", 3, {"int", "int", "int"}},
    {"select", 3, {"int", "fd_set*", "fd_set*"}},
    {"poll", 3, {"struct pollfd*", "unsigned int", "int"}},
    {"readv", 3, {"int", "struct iovec*", "int"}},
    {"writev", 3, {"int", "struct iovec*", "int"}},
    // 4 args
    {"wait4", 4, {"int", "int*", "int", "struct rusage*"}},
    {"send", 4, {"int", "void*", "unsigned long", "int"}},
    {"recv", 4, {"int", "void*", "unsigned long", "int"}},
    {"prctl", 4, {"int", "unsigned long", "unsigned long", "unsigned long"}},
    {"epoll_ctl", 4, {"int", "int", "int", "struct epoll_event*"}},
    {"utimensat", 4, {"int", "char*", "struct timespec*", "int"}},
    {"futex", 4, {"int*", "int", "int", "struct timespec*"}},
    {"rt_sigaction", 4, {"int", "struct sigaction*", "struct sigaction*", "unsigned long"}},
    {"setxattr", 4, {"char*", "char*", "void*", "unsigned long"}},
    {"getxattr", 4, {"char*", "char*", "void*", "unsigned long"}},
    {"removexattr", 4, {"char*", "char*"}},
    {"sched_setparam", 4, {"int", "struct sched_param*", "int", "int"}},
    // 5 args
    {"clone", 5, {"int", "void*", "int", "void*", "void*"}},
    {"mremap", 5, {"void*", "unsigned long", "unsigned long", "int", "void*"}},
    {"pselect6", 5, {"int", "fd_set*", "fd_set*", "fd_set*", "struct timespec*"}},
    {"ppoll", 5, {"struct pollfd*", "unsigned long", "struct timespec*", "sigset_t*"}},
    {"splice", 5, {"int", "unsigned long*", "int", "unsigned long*", "unsigned long"}},
    {"kexec_load", 5, {"unsigned long", "unsigned long", "struct kexec_segment*", "unsigned long", "int"}},
    // 6 args
    {"mmap", 6, {"void*", "unsigned long", "int", "int", "int", "long"}},
    {"recvmmsg", 6, {"int", "struct mmsghdr*", "unsigned int", "unsigned int", "struct timespec*"}},
    {"sendmmsg", 6, {"int", "struct mmsghdr*", "unsigned int", "unsigned int"}},
    {"io_uring_setup", 6, {"unsigned int", "struct io_uring_params*", "unsigned long", "unsigned int", "unsigned int", "unsigned int"}},
    {"fadvise64", 6, {"int", "unsigned long", "unsigned long", "unsigned int"}},
    {NULL, 0, {NULL}}
};

static bool is_valid_line(const char *line) {
    if (strlen(line) <= 1 || line == NULL)
        return false;

    if (strcmp(line, "#ifndef _ASM_UNISTD_64_H\n") == 0 ||
        strcmp(line, "#define _ASM_UNISTD_64_H\n") == 0 ||
        strcmp(line, "#endif /* _ASM_UNISTD_64_H */\n") == 0) {
        return false;
    }
    return true; 
}

char **get_syscall_names() {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    char **syscall_names = NULL;
    int size = 0;
    int i = 0;

    fp = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "r");
    if (fp == NULL)
        return NULL;

    while ((read = getline(&line, &len, fp)) != -1){
        if (is_valid_line(line))
            size++;
    }
    if (line)
        free(line);
    rewind(fp);
    syscall_names = calloc(size + 1, sizeof(char *));
    if (!syscall_names)
        return NULL;
    while ((read = getline(&line, &len, fp)) != -1) {
        if (is_valid_line(line)) { 
            char **split_line = ft_split(line, ' ');
            syscall_names[i] = ft_substr(split_line[1], 5, strlen(split_line[1]));
            i++;
        }
    }
    fclose(fp);
    return syscall_names;
}