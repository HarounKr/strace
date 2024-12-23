#include "../inc/ft_strace.h"

t_exec executable;

void parse_args(int ac, char **av) {

    executable.cmd = strdup(av[1]);
    executable.absolute_path = get_absolute_path(av[1]);
    executable.args = calloc(ac, sizeof(char *));
    if (!executable.args) {
        perror("calloc");
        exit(EXIT_FAILURE);
    } 
    for (int i = 1; i < ac; i++)
        executable.args[i - 1]  = strdup(av[i]);
}

void define_elf_type(uint8_t *file_data) {
    Elf64_Ehdr *file_hdr;
    file_hdr = (Elf64_Ehdr *) file_data;

    if (file_hdr->e_ident[EI_MAG0] != ELFMAG0 || file_hdr->e_ident[EI_MAG1] != ELFMAG1 ||
            file_hdr->e_ident[EI_MAG2] != ELFMAG2 || file_hdr->e_ident[EI_MAG3] != ELFMAG3) {
                fprintf(stderr, "ft_strace: file format not recognized\n ");
                exit(EXIT_FAILURE);
            }
    else if (file_hdr->e_ident[EI_CLASS] == ELFCLASS32)
        executable.elf_type = 32;
    else if (file_hdr->e_ident[EI_CLASS] == ELFCLASS64)
        executable.elf_type = 64;
}

int main(int ac, char **av) {

    struct stat buf;
    uint8_t *file_data;

    if (ac < 2) {
        fprintf(stderr, "Usage : ./%s [executable/command] to trace\n]", av[0]);
        exit(EXIT_FAILURE);
    }
    parse_args(ac, av);
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
    //for (int i = 0; i < buf.st_size; i++) {
   //     printf("%c", file_data[i]);
   // }
    define_elf_type(file_data);
    printf("%d\n ", executable.elf_type);
    munmap(file_data, buf.st_size);
    close(fd);
    return 0;
}  
