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