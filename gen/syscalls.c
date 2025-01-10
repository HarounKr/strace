#include "../inc/ft_strace.h"

// https://syscall.sh/
// t_syscall syscalls[] = {
//     // 0 arg
//     {"getpid", 0, {NULL}, "int"},
//     {"getppid", 0, {NULL}, "int"},
//     {"getuid", 0, {NULL}, "unsigned int"},
//     {"geteuid", 0, {NULL}, "unsigned int"},
//     {"getgid", 0, {NULL}, "unsigned int"},
//     {"getegid", 0, {NULL}, "unsigned int"},
//     {"setsid", 0, {NULL}, "int"},
//     {"sched_yield", 0, {NULL}, "int"},
//     {"fork", 0, {NULL}, "int"},
//     {"vfork", 0, {NULL}, "int"},
//     {"sync", 0, {NULL}, "void"},
//     {"pause", 0, {NULL}, "int"},
//     {"gettid", 0, {NULL}, "int"},
//     {"times", 0, {NULL}, "long"},
//     {"iopl", 0, {NULL}, "int"},
//     {"vhangup", 0, {NULL}, "int"},
//     {"mlockall", 0, {NULL}, "int"},
//     {"munlockall", 0, {NULL}, "int"},
//     {"sysinfo", 0, {NULL}, "int"},
//     {"sched_get_priority_max", 0, {NULL}, "int"},
//     {"sched_get_priority_min", 0, {NULL}, "int"},
//     {"rt_sigreturn", 0, {NULL}, "int"},
//     // 1 arg
//     {"exit", 1, {"int"}, "void"},
//     {"exit_group", 1, {"int"}, "void"},
//     {"close", 1, {"int"}, "int"},
//     {"unlink", 1, {"char*"}, "int"},
//     {"rmdir", 1, {"char*"}, "int"},
//     {"syncfs", 1, {"int"}, "int"},
//     {"fsync", 1, {"int"}, "int"},
//     {"chdir", 1, {"char*"}, "int"},
//     {"fchdir", 1, {"int"}, "int"},
//     {"brk", 1, {"addr"}, "void*"},
//     {"setuid", 1, {"unsigned int"}, "int"},
//     {"setgid", 1, {"unsigned int"}, "int"},
//     {"reboot", 1, {"int"}, "int"},
//     {"umask", 1, {"unsigned int"}, "unsigned int"},
//     {"pipe", 1, {"int*"}, "int"},
//     {"dup", 1, {"int"}, "int"},
//     {"dup2", 1, {"int"}, "int"},
//     {"getpriority", 1, {"int"}, "int"},
//     {"getpgid", 1, {"int"}, "int"},
//     {"personality", 1, {"unsigned int"}, "int"},
//     {"set_tid_address", 1, {"addr"}, "int"},
//     // 2 args
//     {"arch_prctl", 2, {"addr", "addr"}, "int"},
//     {"open", 2, {"char*", "int"}, "int"},
//     {"rename", 2, {"char*", "char*"}, "int"},
//     {"mkdir", 2, {"char*", "unsigned int"}, "int"},
//     {"chmod", 2, {"char*", "unsigned int"}, "int"},
//     {"munmap", 2, {"void*", "unsigned long"}, "int"},
//     {"fstat", 2, {"int", "addr"}, "int"},
//     {"readlink", 2, {"char*", "char*"}, "long"},
//     {"kill", 2, {"int", "int"}, "int"},
//     {"ftruncate", 2, {"int", "unsigned long"}, "int"},
//     {"truncate", 2, {"char*", "unsigned long"}, "int"},
//     {"ioctl", 2, {"int", "unsigned long"}, "int"},
//     {"access", 2, {"char*", "int"}, "int"},
//     {"symlink", 2, {"char*", "char*"}, "int"},
//     {"link", 2, {"char*", "char*"}, "int"},
//     {"utime", 2, {"char*", "addr"}, "int"},
//     {"utimes", 2, {"char*", "addr"}, "int"},
//     {"stat", 2, {"char*", "addr"}, "int"},
//     {"lstat", 2, {"char*", "addr"}, "int"},
//     {"mount", 2, {"char*", "char*"}, "int"},
//     {"umount2", 2, {"char*", "int"}, "int"},
//     {"set_robust_list", 2, {"addr", "unsigned long"}, "int"},
//     // 3 args
//     {"read", 3, {"int", "char*", "unsigned long"}, "long"},
//     {"write", 3, {"int", "char*", "unsigned long"}, "long"},
//     {"lseek", 3, {"int", "long", "int"}, "long"},
//     {"socket", 3, {"int", "int", "int"}, "int"},
//     {"bind", 3, {"int", "addr", "unsigned int"}, "int"},
//     {"connect", 3, {"int", "addr", "unsigned int"}, "int"},
//     {"accept", 3, {"int", "addr", "unsigned int*"}, "int"},
//     {"execve", 3, {"char*", "char**", "char**"}, "int"},
//     {"mprotect", 3, {"addr", "unsigned long", "int"}, "int"},
//     {"recvfrom", 3, {"int", "void*", "unsigned long"}, "long"},
//     {"sendto", 3, {"int", "void*", "unsigned long"}, "long"},
//     {"shutdown", 3, {"int", "int"}, "int"},
//     {"recvmsg", 3, {"int", "addr", "int"}, "long"},
//     {"sendmsg", 3, {"int", "addr", "int"}, "long"},
//     {"pread64", 3, {"int", "addr", "unsigned long"}, "long"},
//     {"pwrite64", 3, {"int", "void*", "unsigned long"}, "long"},
//     {"getpeername", 3, {"int", "addr", "unsigned int*"}, "int"},
//     {"getsockname", 3, {"int", "addr", "unsigned int*"}, "int"},
//     {"getsockopt", 3, {"int", "int", "int"}, "int"},
//     {"setsockopt", 3, {"int", "int", "int"}, "int"},
//     {"select", 3, {"int", "fd_set*", "fd_set*"}, "int"},
//     {"poll", 3, {"addr", "unsigned int", "int"}, "int"},
//     {"readv", 3, {"int", "addr", "int"}, "long"},
//     {"writev", 3, {"int", "addr", "int"}, "long"},
//     {"openat", 3, {"int", "char*", "int"}, "int"},
//     {"getrandom", 3, {"addr", "unsigned int", "unsigned int"}, "long"},
//     // 4 args
//     {"wait4", 4, {"int", "int*", "int", "addr"}, "int"},
//     {"send", 4, {"int", "void*", "unsigned long", "int"}, "long"},
//     {"recv", 4, {"int", "void*", "unsigned long", "int"}, "long"},
//     {"prctl", 4, {"int", "unsigned long", "unsigned long", "unsigned long"}, "int"},
//     {"epoll_ctl", 4, {"int", "int", "int", "addr"}, "int"},
//     {"utimensat", 4, {"int", "char*", "addr", "int"}, "int"},
//     {"futex", 4, {"int*", "int", "int", "addr"}, "int"},
//     {"rt_sigaction", 4, {"int", "addr", "addr", "unsigned long"}, "int"},
//     {"setxattr", 4, {"char*", "char*", "void*", "unsigned long"}, "int"},
//     {"getxattr", 4, {"char*", "char*", "void*", "unsigned long"}, "long"},
//     {"removexattr", 4, {"char*", "char*"}, "int"},
//     {"sched_setparam", 4, {"int", "addr", "int", "int"}, "int"},
//     {"rseq", 4, {"addr", "addr", "int", "addr"}, "int"},
//     // 5 args
//     {"clone", 5, {"int", "void*", "int", "void*", "void*"}, "int"},
//     {"mremap", 5, {"void*", "unsigned long", "unsigned long", "int", "void*"}, "void*"},
//     {"pselect6", 5, {"int", "fd_set*", "fd_set*", "fd_set*", "addr"}, "int"},
//     {"ppoll", 5, {"addr", "unsigned long", "addr", "sigset_t*"}, "int"},
//     {"splice", 5, {"int", "unsigned long*", "int", "unsigned long*", "unsigned long"}, "long"},
//     {"kexec_load", 5, {"unsigned long", "unsigned long", "addr", "unsigned long", "int"}, "int"},
//     // 6 args
//     {"mmap", 6, {"void*", "unsigned long", "int", "int", "int", "long"}, "void*"},
//     {"recvmmsg", 6, {"int", "addr", "unsigned int", "unsigned int", "addr"}, "int"},
//     {"sendmmsg", 6, {"int", "addr", "unsigned int", "unsigned int"}, "int"},
//     {"io_uring_setup", 6, {"unsigned int", "addr", "unsigned long", "unsigned int", "unsigned int", "unsigned int"}, "int"},
//     {"fadvise64", 6, {"int", "unsigned long", "unsigned long", "unsigned int"}, "int"},
//     {NULL, 0, {NULL}, NULL}
// };


// static bool is_valid_line(const char *line) {
//     if (strlen(line) <= 1 || line == NULL)
//         return false;

//     if (strcmp(line, "#ifndef _ASM_UNISTD_64_H\n") == 0 ||
//         strcmp(line, "#define _ASM_UNISTD_64_H\n") == 0 ||
//         strcmp(line, "#endif /* _ASM_UNISTD_64_H */\n") == 0) {
//         return false;
//     }
//     return true; 
// }

// char **get_syscall_names() {
//     FILE * fp;
//     char * line = NULL;
//     size_t len = 0;
//     ssize_t read;
//     char **syscall_names = NULL;
//     int size = 0;
//     int i = 0;

//     fp = fopen("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", "r");
//     if (fp == NULL)
//         return NULL;

//     while ((read = getline(&line, &len, fp)) != -1){
//         if (is_valid_line(line))
//             size++;
//     }
//     if (line) {
//         free(line);
//         line = NULL;
//     }
//     rewind(fp);
//     syscall_names = calloc(size + 1, sizeof(char *));
//     if (!syscall_names) {
//         fclose(fp);
//         return NULL;
//     }
//     while ((read = getline(&line, &len, fp)) != -1) {
//         if (is_valid_line(line)) { 
//             char **split_line = ft_split(line, ' ');
//             syscall_names[i] = ft_substr(split_line[1], 5, strlen(split_line[1]));
//             free_tab(split_line);
//             i++;
//         }
//     }
//     if (line) {
//         free(line);
//         line = NULL;
//     }
//     fclose(fp);
//     return syscall_names;
// }