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

typedef struct s_output {
    char *arg1;
    char *arg2;
    char *arg3;
    char *arg4;
    char *arg5;
    char *arg6;
}  t_output;

extern  t_syscall syscalls[];

void	free_tab(char **tab);
void    free_exec_struct(t_exec executable);

int     trace_exec(t_exec executable);
bool    is_addr_mapped(pid_t pid, unsigned long addr);
size_t  tab_size(char **tab);

char    *get_absolute_path(const char *cmd );
char	*ft_strjoin(char const *s1, char const *s2);
char	**ft_split(char const *str, char set);
char    **get_syscall_names();
char	*ft_substr(char const *s, unsigned int start, size_t len);
char    *to_string(char **tab);