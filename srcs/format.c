#include "../inc/ft_strace.h"


char *to_string(char **tab) {
    if (tab == NULL)
        return strdup("[]");

    size_t nb_elem = tab_size(tab);

    if (nb_elem == 0)
        return strdup("[]");

    size_t total_len = 3 + 4 * nb_elem; // [ ] \0 + pour chaque élément: 4 de base
    size_t i;
    for (i = 0; i < nb_elem; i++)
        total_len += strlen(tab[i]); 

    // On enlève 2 pour retirer la dernière ", "
    total_len -= 2;

    char *str = malloc(total_len);
    if (!str)
        return NULL;

    size_t ret = 0;

    str[ret++] = '[';
    for (i = 0; i < nb_elem; i++) {
        // Ajouter " + la chaîne + "
        ret += snprintf(str + ret, total_len - ret, "\"%s\"", tab[i]);

        // Si ce n'est pas le dernier élément, on ajoute ", "
        if (i < nb_elem - 1)
            ret += snprintf(str + ret, total_len - ret, ", ");
        
    }
    str[ret++] = ']';
    str[ret] = '\0';

    return str;
}

static int format_args(user_regs_struct regs, char *arg_type, pid_t pid, unsigned long long int reg_addr) {
    if (!strcmp(arg_type, "int") || !strcmp(arg_type, "long"))
        fprintf(stdout, "%ld", peekint(reg_addr));
    else if (!strcmp(arg_type, "unsigned long") || !strcmp(arg_type, "unsigned int"))
        fprintf(stdout, "%lu", peekint(reg_addr));
    else if (!strcmp(arg_type, "char*")) {
        char *str = peekdata(pid, regs.rdi, 256);
        if (str) {
            fprintf(stdout, "%s", (char *)peekdata(pid, reg_addr, 256));
            free(str);
        } else
            return 1;
    }
    else if (!strcmp(arg_type, "char**")) {
        char doubleptr = peekdoubleptr(pid, reg_addr);
        if (doubleptr) {

        } else
            return 1;
    }
    else if (!strcmp(arg_type, "void*"))
        fprintf(stdout, "void*");
    else if (!strcmp(arg_type, "int*")) {
        int *value = peekdata(pid, reg_addr, sizeof(int));
        if (value) {
            fprintf(stdout, "%d", value[0]);
            free(value);
        } else
            return 1;
    }
    else if (!strncmp(arg_type, "struct", strlen("struct")) || !strncmp(arg_type, "sigset_t", strlen("sigset_t"))
        )
        fprintf(stdout, "%s", arg_type);

    return 0;
}

void format_output(user_regs_struct regs, int n_args, int index, pid_t pid) {
    if (n_args == 0) {
        fprintf(stdout, "void)");
        return ;
    }

    unsigned long long int regs_addr[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

    for (int i = 0; syscalls[index].arg_types[i]; i++) {
        unsigned long long int addr = regs_addr[i];
        
        char *arg_type = syscalls[index].arg_types[i];
        if (format_args(regs, arg_type, pid, addr))
            fprintf(stdout, "NULL");
    }
}