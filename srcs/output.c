#include "../inc/ft_strace.h"

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
    if (n_args == 0) {
        fprintf(stdout, "void)");
        return ;
    }
    fprintf(stdout, "%s(", syscall->name);

    for (int i = 0; i < n_args; i++) {
        uint64_t addr = regs_addr[i];
        format_and_print_arg(syscall->arg_types[i], pid, addr);
        if (i < n_args - 1)
            fprintf(stdout, ", ");
        
    }
    fprintf(stdout, ") =  ");
}