#include "../inc/ft_strace.h"

t_exec executable;

static int init_exec_struct(int ac, char **av, char **envp) {
    int len_envp = 0;

    executable.absolute_path = get_absolute_path(av[1]);
    if (access(executable.absolute_path, X_OK))
        return 1;
    executable.cmd = strdup(av[1]);
    executable.args = calloc(ac, sizeof(char *));
    if (!executable.args)
        return 1;
    for (int i = 1; i < ac; i++)
        executable.args[i - 1]  = strdup(av[i]);
    while (envp[len_envp])
        len_envp++;
    executable.envp = envp;
    executable.syscall_names = get_syscall_names();
    if (executable.syscall_names == NULL) {
        fprintf(stderr, "Failed to load syscall names.\n");
        return 1;
    }

    return 0;
}

static int define_elf_type(uint8_t *file_data) {
    Elf64_Ehdr *file_hdr;

    file_hdr = (Elf64_Ehdr *) file_data;

    if (file_hdr->e_ident[EI_MAG0] != ELFMAG0 || file_hdr->e_ident[EI_MAG1] != ELFMAG1 ||
            file_hdr->e_ident[EI_MAG2] != ELFMAG2 || file_hdr->e_ident[EI_MAG3] != ELFMAG3)
                return 1;
    else if (file_hdr->e_ident[EI_CLASS] == ELFCLASS32)
        executable.elf_type = 32;
    else if (file_hdr->e_ident[EI_CLASS] == ELFCLASS64)
        executable.elf_type = 64;
    
    return 0;
}

int main(int ac, char **av, char **envp) {

    struct stat buf;
    uint8_t *file_data;
    // printf("Size of uint64_t: %zu bytes\n", sizeof(uint64_t));
    // printf("Size of unsigned long: %zu bytes\n", sizeof(unsigned long));
    // printf("Size of unsigned long long: %zu bytes\n", sizeof(unsigned long long));
    if (ac < 2) {
        fprintf(stderr, "Usage : %s [executable/command] to trace\n]", av[0]);
        exit(EXIT_FAILURE);
    }
    if (init_exec_struct(ac, av, envp)) {
        perror("ft_strace: ");
        free_exec_struct(executable);
        exit(EXIT_FAILURE);
    } 
    int fd = open(executable.absolute_path, O_RDONLY, S_IRUSR);
    if (fd == -1) {
        perror("ft_strace: ");
        exit(EXIT_FAILURE);
    }
    if (fstat(fd, &buf) != 0) {
        close(fd);
        fprintf(stderr, "ft_strace: %s couldn't get file size\n", av[1]);
        exit(EXIT_FAILURE);
    }
    else if (S_ISDIR(buf.st_mode)) {
        close(fd);
        fprintf(stderr, "ft_strace: %s is a directory\n", av[1]);
        exit(EXIT_FAILURE);
    }
    file_data = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) { 
        fprintf(stderr, "ft_strace: %s: mapped memory failed\n", av[1]);
        exit(EXIT_FAILURE);
    }
    if (define_elf_type(file_data)) {
        fprintf(stderr, "ft_strace: file format not recognized\n ");
        munmap(file_data, buf.st_size);
        free_exec_struct(executable);
        close(fd);
        exit(EXIT_FAILURE);
    } 
    munmap(file_data, buf.st_size);
    close(fd);
    trace_exec(executable);
    free_exec_struct(executable);
    return 0;
}

    //for (int i = 0; i < buf.st_size; i++) {
   //     printf("%c", file_data[i]);
   // }