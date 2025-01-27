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
            fprintf(stdout,"%c", c);
        } else {
            fprintf(stdout,"\\%01o", c);
        }
    }
    fprintf(stdout, "\"...");
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

void print_ret_value(uint64_t ret_value, char *ret_type) {
    if (!strcmp(ret_type, "int")) {
        fprintf(stdout, "%d\n", (int)ret_value);
    } else if (!strcmp(ret_type, "unsigned int")) {
        fprintf(stdout, "%u\n", (unsigned int)ret_value);
    } else if (!strncmp(ret_type, "void", strlen("void"))) {
        fprintf(stdout, "%p\n", (void *)ret_value);
    } else if (!strcmp(ret_type, "long")) {
        fprintf(stdout, "%ld\n", (long)ret_value);
    } else {
        fprintf(stdout, "%lu\n", ret_value);
    }
}

static void format_and_print_arg(char *arg_type, pid_t pid, uint64_t reg_addr) {
    for (int i = 0; types[i].name != NULL; i++) {
        if (!strcmp(arg_type, types[i].name)) {
            types[i].func(arg_type, pid, reg_addr);
        }
    }
}

void print_args(uint64_t *regs_addr, int n_args, t_syscall *syscall, pid_t pid) {
    fprintf(stdout, "%s(", syscall->name);
    if (n_args == 0) {
        fprintf(stdout, "void) = ");
        return ;
    }

    for (int i = 0; i < n_args; i++) {
        uint64_t addr = regs_addr[i];
        format_and_print_arg(syscall->arg_types[i], pid, addr);
        if (i < n_args - 1)
            fprintf(stdout, ", ");
        
    }
    fprintf(stdout, ") =  ");
}