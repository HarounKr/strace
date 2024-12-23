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

#define PATH_MAX 4096  

typedef struct s_exec {
    char *cmd;
    char *absolute_path;
    char **args;
    int elf_type;
} t_exec;


void	free_tab(char **tab);

char    *get_absolute_path(const char *cmd );
char	*ft_strjoin(char const *s1, char const *s2);
char	**ft_split(char const *str, char set);