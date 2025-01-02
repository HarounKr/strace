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
#include <linux/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
//#include <sys/siginfo.h>

#define PATH_MAX 4096

typedef struct user_regs_struct user_regs_struct;
typedef struct iovec iovec;

typedef struct s_exec {
    char *cmd;
    char *absolute_path;
    char **args;
    char **envp;
    int elf_type;
} t_exec;

typedef struct s_sycall {
    char *name;
    int arg_count;
    char *arg_types[6];
} t_syscall;

typedef struct s_type {
    char *name;
    void (*func)(char *, pid_t, unsigned long long int);
} t_type;


extern  t_syscall syscalls[];
extern t_type types[];

void	free_tab(char **tab);
void    free_exec_struct(t_exec executable);
void    format_output(user_regs_struct regs, int n_args, int index, pid_t pid);

int     trace_exec(t_exec executable);
size_t  tab_size(char **tab);
unsigned long peekptr(pid_t pid, unsigned long addr);

char    *get_absolute_path(const char *cmd);
char	*ft_substr(char const *s, unsigned int start, size_t len);
char    *to_string(char **tab);
void    *peekdata(pid_t pid, unsigned long addr, size_t size);

char    **peekdoubleptr(pid_t pid, unsigned long addr) ;
char	**ft_split(char const *str, char set);
char    **get_syscall_names();