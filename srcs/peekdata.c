#include "../inc/ft_strace.h"

bool is_addr_mapped(pid_t pid, unsigned long addr) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
        perror("fopen");
        return false;
    }

    char line[512];
    unsigned long start, end;
    bool found = false;

    while (fgets(line, sizeof(line), fp)) {
        // format : "start-end perms offset dev inode pathname"
        // exemple : 45cd9630000-745cd9631000 rw-p 00005000 08:01 4114                       /usr/lib/x86_64-linux-gnu/libgmodule-2.0.so.0.7200.4
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (addr >= start && addr < end) {
                found = true;
                break;
            }
        }
    }
    fclose(fp);
    return found;
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