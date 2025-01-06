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
    char **syscall_names;
    int elf_type;
} t_exec;

typedef struct s_sycall {
    char *name;
    int arg_count;
    char *arg_types[6];
    char *ret_type;
} t_syscall;

typedef struct s_type {
    char *name;
    void (*func)(char *, pid_t, long long int);
} t_type;

struct user_regs_struct_32 {
  long int ebx;
  long int ecx;
  long int edx;
  long int esi;
  long int edi;
  long int ebp;
  long int eax;
  long int xds;
  long int xes;
  long int xfs;
  long int xgs;
  long int orig_eax;
  long int eip;
  long int xcs;
  long int eflags;
  long int esp;
  long int xss;
} ;

typedef struct s_unified_regs {
    struct user_regs_struct regs64;
    struct user_regs_struct_32 regs32;
} t_unified_regs;

extern  t_syscall syscalls[];
extern t_type types[];

void	free_tab(char **tab);
void    free_exec_struct(t_exec executable);
void    format_output(long long int *regs_addr, int n_args, int index, pid_t pid);

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