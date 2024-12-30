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