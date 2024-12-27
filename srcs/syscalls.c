#include "../inc/ft_strace.h"

// https://syscall.sh/

Syscall syscalls[] = {
    // 0 arg
    {"getpid", 0, {NULL}},
    {"getppid", 0, {NULL}},
    {"getuid", 0, {NULL}},
    {"geteuid", 0, {NULL}},
    {"getgid", 0, {NULL}},
    {"getegid", 0, {NULL}},
    {"fork", 0, {NULL}},
    {"vfork", 0, {NULL}},
    {"sync", 0, {NULL}},

    // 1 arg
    {"exit", 1, {"int"}},
    {"close", 1, {"int"}},
    {"unlink", 1, {"char*"}},
    {"rmdir", 1, {"char*"}},
    {"syncfs", 1, {"int"}},
    {"fsync", 1, {"int"}},
    {"chdir", 1, {"char*"}},
    {"fchdir", 1, {"int"}},
    {"brk", 1, {"void*"}},
    {"setuid", 1, {"uid_t"}},
    {"setgid", 1, {"gid_t"}},

    // 2 args
    {"open", 2, {"char*", "int"}},
    {"rename", 2, {"char*", "char*"}},
    {"mkdir", 2, {"char*", "mode_t"}},
    {"chmod", 2, {"char*", "mode_t"}},
    {"munmap", 2, {"void*", "size_t"}},
    {"fstat", 2, {"int", "struct stat*"}},

    // 3 args
    {"read", 3, {"int", "char*", "size_t"}},
    {"write", 3, {"int", "char*", "size_t"}},
    {"lseek", 3, {"int", "off_t", "int"}},
    {"socket", 3, {"int", "int", "int"}},
    {"bind", 3, {"int", "struct sockaddr*", "socklen_t"}},
    {"connect", 3, {"int", "struct sockaddr*", "socklen_t"}},
    {"accept", 3, {"int", "struct sockaddr*", "socklen_t*"}},
    {"execve", 3, {"char*", "char**", "char**"}},
    {"mprotect", 3, {"void*", "size_t", "int"}},

    // 4 args
    {"wait4", 4, {"pid_t", "int*", "int", "struct rusage*"}},
    {"send", 4, {"int", "void*", "size_t", "int"}},
    {"recv", 4, {"int", "void*", "size_t", "int"}},

    // 5 args
    {"clone", 5, {"int", "void*", "int", "void*", "void*"}},
    {"mremap", 5, {"void*", "size_t", "size_t", "int", "void*"}},

    // 6 args
    {"mmap", 6, {"void*", "size_t", "int", "int", "int", "off_t"}},

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