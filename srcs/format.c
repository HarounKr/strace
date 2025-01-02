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

static void format_and_print_arg(char *arg_type, pid_t pid, unsigned long long int reg_addr) {
    for (int i = 0; types[i].name != NULL; i++) {
        if (!strcmp(arg_type, types[i].name)) {
            printf("\n");
            types[i].func(arg_type, pid, reg_addr);
        }
    }
}

void format_output(user_regs_struct regs, int n_args, int index, pid_t pid) {
    if (n_args == 0) {
        fprintf(stdout, "void)");
        return ;
    }
    int width = 0;
    fprintf(stdout, "%s(\n", syscalls[index].name);

    unsigned long long int regs_addr[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

    for (int i = 0; syscalls[index].arg_types[i]; i++) {
        unsigned long long int addr = regs_addr[i];

        char *arg_type = syscalls[index].arg_types[i];
        
            format_and_print_arg(arg_type, pid, addr);
            if (i < n_args - 1)
                fprintf(stdout, ", ");
        
    }
    if (syscalls[index].arg_count <= 1)
        width = 30;
    fprintf(stdout, ") =%*c", width, ' ');
}