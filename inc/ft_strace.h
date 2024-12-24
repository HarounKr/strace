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
extern const char* syscall_names[];


typedef struct s_exec {
    char *cmd;
    char *absolute_path;
    char **args;
    char **envp;
    int elf_type;
} t_exec;


void	free_tab(char **tab);
void    free_exec_struct(t_exec executable);

int     trace_exec(t_exec executable);

char    *get_absolute_path(const char *cmd );
char	*ft_strjoin(char const *s1, char const *s2);
char	**ft_split(char const *str, char set);