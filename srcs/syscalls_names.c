#include "../inc/ft_strace.h"


int is_valid_line(const char *line) {
    if (strlen(line) <= 1 || line == NULL)
        return 0;

    if (strcmp(line, "#ifndef _ASM_UNISTD_64_H\n") == 0 ||
        strcmp(line, "#define _ASM_UNISTD_64_H\n") == 0 ||
        strcmp(line, "#endif /* _ASM_UNISTD_64_H */\n") == 0) {
        return 0;
    }
    return 1; 
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