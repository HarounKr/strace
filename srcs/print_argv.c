#include "../inc/ft_strace.h"

void print_read_str(char *buf, int len) {
    int i;
    fprintf(stdout, "\"");

    for (i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if (c == '\n') {
            fprintf(stdout,"\\n");
        } else if (c == '\t') {
            fprintf(stdout,"\\t");
        } else if (isprint(c)) {
            fprintf("%c", c);
        } else {
            fprintf("\\%01o", c);
        }
    }
    printf("\"...");
}

static void int_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    (void) arg_type;
    (void) pid;
    fprintf(stdout, "%d", (int) reg_addr);
}

static void long_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    (void) arg_type;
    (void) pid;
    fprintf(stdout, "%ld", (long) reg_addr);
}

void unsigned_int_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    (void) arg_type;
    (void) pid;
    fprintf(stdout, "%u", (unsigned int) reg_addr);
}

static void unsigned_long_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    (void) arg_type;
    (void) pid;
    fprintf(stdout, "%lu", (unsigned long int) reg_addr);
}

static void charptr_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    char *str = peekdata(pid, reg_addr, 4096, sizeof(char));
    if (str) {
        if (read_syscall)
            print_read_str(str, 40);
        else
            fprintf(stdout, "\"%s\"", str);
        free(str);
    } else
        fprintf(stdout, "%s", arg_type);
}

static void chardoubleptr_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    char **doubleptr = peekdoubleptr(pid, reg_addr);
    if (doubleptr) {
        char *str = to_string(doubleptr);
        fprintf(stdout, "%s", str);
        free(str);
        free_tab(doubleptr);
    } else
        fprintf(stdout, "%s", arg_type);
}

static void intptr_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    int *value = peekdata(pid, reg_addr, 4096, sizeof(int));
    if (value) {
        fprintf(stdout, "%d", value[0]);
        free(value);
    } else
        fprintf(stdout, "%s", arg_type);
}

static void addr_type(char *arg_type, pid_t pid, uint64_t reg_addr) {
    (void)arg_type;
    (void)pid;
    fprintf(stdout, "%p", (void *)reg_addr);
}

t_type types[] = {
    {"int", int_type},
    {"long", long_type},
    {"unsigned int", unsigned_int_type},
    {"unsigned long", unsigned_long_type},
    {"char *", charptr_type},
    {"char **", chardoubleptr_type},
    {"int *", intptr_type},
    {"void", addr_type},
    {"void *", addr_type},
    {"addr", addr_type},
    {NULL, NULL},
};