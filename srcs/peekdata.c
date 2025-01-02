#include "../inc/ft_strace.h"

long int peekint(unsigned long addr){
    return (long int) addr;
}

unsigned long peekptr(pid_t pid, unsigned long addr) {
    if (is_addr_mapped(pid, addr)) {
         unsigned long val;
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return -1;
        }
        off_t pos = lseek(fd, (off_t)addr, SEEK_SET);
        if (pos == -1) {
            close(fd);
            return -1;
        }

        ssize_t n_read = read(fd, &val, sizeof(val));
        if (n_read < 0) {
            close(fd);
            return -1;
        } 
        close(fd);
        return val;
    }
    return -1;
}

void *peekdata(pid_t pid, unsigned long addr, size_t size) {

    if (is_addr_mapped(pid, addr)) {
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return NULL;
        }

        void *buf = malloc(size);
        if (!buf) {
            close(fd);
            return NULL;
        }

        off_t pos = lseek(fd, (off_t)addr, SEEK_SET);
        if (pos == -1) {
            free(buf);
            close(fd);
            return NULL;
        }

        ssize_t n_read = read(fd, buf, size);
        if (n_read < (ssize_t)size) {
            free(buf);
            close(fd);
            return NULL;
        }

        close(fd);
        return buf;
    }
    return NULL;
}


char **peekdoubleptr(pid_t pid, unsigned long addr) {

    bool is_alive = true;
    unsigned long i = 0;
    char **doubleptr = NULL;

    while (is_alive) {
        unsigned long ptr_value = peekptr(pid, addr + i * sizeof(ptr_value));
        if (ptr_value == 0 || (long) ptr_value == -1)
            break;
        i++;
    }
    if (i > 10) {
        doubleptr = calloc(2, sizeof(char *));
        char buf[256];
        snprintf(buf, 256, "0x%lx /* %d vars */", addr, (int) i);
        doubleptr[0] = strdup(buf);
    }
    else {
        doubleptr = calloc(i + 1, sizeof(char *));
        i = 0;
        while (is_alive) {
            unsigned long ptr_value = peekptr(pid, addr + i * sizeof(ptr_value));
            if (ptr_value == 0 || (long) ptr_value == -1)
                break;
            char *str = peekdata(pid, ptr_value, 256);
            if (str == NULL) {
                free(str);
                break ;
            }
            doubleptr[i] = str;
            i++;
        }
    }
    return  doubleptr;
}