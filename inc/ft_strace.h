#pragma once
#define _XOPEN_SOURCE 700

#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <asm-generic/unistd.h>
//#include <linux/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <ctype.h>
//#include <sys/siginfo.h>

#define PATH_MAX 4096

typedef struct iovec iovec;

typedef struct s_exec {
    char *cmd;
    char *absolute_path;
    char **args;
    char **envp;
    //char **syscall_names;
    int elf_type;
} t_exec;

typedef struct s_sycall {
    int num;
    char *name;
    int arg_count;
    char *arg_types[6];
    char *ret_type;
} t_syscall;

typedef struct s_type {
    char *name;
    void (*func)(char *, pid_t, uint64_t);
} t_type;

struct i386_user_regs_struct {
	uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
    uint32_t orig_eax;
    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t esp;
    uint32_t ss;
};

union x86_regs_union {
    struct user_regs_struct      regs64;
    struct i386_user_regs_struct regs32;
};
extern  t_syscall syscalls32[];
extern  t_syscall syscalls64[];

extern t_type types[];
extern int read_buffer_size;
extern bool read_syscall;

void	free_tab(char **tab);
void    free_exec_struct(t_exec *exec);
void    print_args(uint64_t *regs_addr, int n_args, t_syscall *syscall, pid_t pid);
void    print_ret_value(uint64_t ret_value, char *ret_type);
void    debug_syscall(t_syscall *syscall);
void    sigset_empty();
void    sigset_blocked();
void    handle_sig(int signum, pid_t pid);

int     trace_exec(t_exec *exec);
size_t  tab_size(char **tab);
unsigned long peekptr(pid_t pid, unsigned long addr);
bool    is_read_syscall(int syscall_num);

char    *get_absolute_path(const char *cmd);
char	*ft_substr(char const *s, unsigned int start, size_t len);
char    *to_string(char **tab);
void    *peekdata(pid_t pid, unsigned long addr, size_t size, size_t sizeof_type);

char    **peekdoubleptr(pid_t pid, unsigned long addr) ;
char	**ft_split(char const *str, char set);
//char    **get_syscall_names();