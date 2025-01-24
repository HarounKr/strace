#include "../inc/ft_strace.h"

bool read_syscall = false;

static int init_exec_struct(int ac, char **av, char **envp, t_exec *exec) {
    int len_envp = 0;

    exec->absolute_path = get_absolute_path(av[1]);
    if (access(exec->absolute_path, X_OK))
        return -1;
    exec->cmd = strdup(av[1]);
    exec->args = calloc(ac, sizeof(char *));
    if (!exec->args)
        return -1;
    for (int i = 1; i < ac; i++)
        exec->args[i - 1]  = strdup(av[i]);
    while (envp[len_envp])
        len_envp++;
    exec->envp = envp;
    //exec->syscall_names = get_syscall_names();
    // if (exec->syscall_names == NULL) {
    //     fprintf(stderr, "Failed to load syscall names.\n");
    //     return -1;
    // }
    return 0;
}

static int is_not_elf(int fd) {
    unsigned char header[64];

    ssize_t bytes_read = read(fd, header, sizeof(header));
    if (bytes_read < 0 || (header[0] != 0x7f && header[1] != 'E' && header[2] != 'L' && header[3] != 'F')) {
        close(fd);
        return -1;
    }
    
    return 0;
}

int main(int ac, char **av, char **envp) {

    struct stat buf;
    t_exec *exec = calloc(sizeof(t_exec), 1);

    if (!exec) {
        perror("calloc ");
        exit(EXIT_FAILURE);
    }

    if (ac < 2) {
        fprintf(stderr, "Usage : %s [exec/command] to trace\n]", av[0]);
        exit(EXIT_FAILURE);
    }
    if (init_exec_struct(ac, av, envp, exec)) {
        perror("ft_strace: ");
        free_exec_struct(exec);
        exit(EXIT_FAILURE);
    }
    int fd = open(exec->absolute_path, O_RDONLY, S_IRUSR);
    if (fd == -1) {
        perror("open: ");
        exit(EXIT_FAILURE);
    }
    if (fstat(fd, &buf) != 0) {
        close(fd);
        fprintf(stderr, "ft_strace: %s couldn't get file size\n", av[1]);
        exit(EXIT_FAILURE);
    } else if (S_ISDIR(buf.st_mode)) {
        close(fd);
        fprintf(stderr, "ft_strace: %s is a directory\n", av[1]);
        exit(EXIT_FAILURE);
    }
   
    if (is_not_elf(fd)) {
        fprintf(stderr, "ft_strace: Exec format error\n ");
        free_exec_struct(exec);
        free(exec);
        exit(EXIT_FAILURE);
    }
    close(fd);
    trace_exec(exec);
    free_exec_struct(exec);
    free(exec);
    return 0;
}