#include "../inc/ft_strace.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	size_t	i;
	size_t	s_len;
	char	*new;

	if (!s)
		return (NULL);
	s_len = strlen(s);
	if (start >= s_len)
		return (strdup(""));
	if (len > s_len - start)
		len = s_len - start;

	new = calloc(len + 1, sizeof(*new));
	if (!new)
		return (NULL);

	i = 0;
	while (i < len && s[start])
	{
		new[i] = s[start];
		i++;
		start++;
	}
	new[i] = '\0';
	return (new);
}

static char	*ft_strndup(char const *s, size_t n)
{
	char	*dest;
	size_t	i;

	i = 0;
	dest = (char *)malloc(n + 1);
	if (dest == NULL)
		return (NULL);
	while (i < n)
	{
		dest[i] = s[i];
		i++;
	}
	dest[i] = '\0';
	return (dest);
}

static int	ft_countwords(char *str, char set)
{
	int	i;
	int	len;

	len = 0;
	i = 0;
	if (strlen(str) == 0)
		return (0);
	if (str[0] != set)
		len++;
	while (str[i])
	{
		if (str[i] == set)
		{
			if (str[i] == set && (str[i + 1] != set && str[i + 1] != '\0'))
				len++;
		}
		i++;
	}
	return (len);
}

char	**ft_split(char const *str, char set)
{
	char	**tab;
	int		i;
	int		m_tab;
	int		len_word;

	m_tab = 0;
	i = -1;
	if (!str)
		return (NULL);
	tab = calloc(sizeof(tab), (ft_countwords((char *)str, set) + 1));
	if (!tab)
		return (NULL);
	while (str[++i])
	{
		len_word = 0;
		if (str[i] != set)
		{
			while (str[i + len_word] != set && str[i + len_word] != '\0')
				len_word++;
			tab[m_tab++] = ft_strndup(str + i, len_word);
			i = i + len_word - 1;
		}
	}
	tab[m_tab] = 0;
	return (tab);
}

void	free_tab(char **tab)
{
	int	i;

	i = 0;
	while (tab[i])
	{
		free(tab[i]);
		tab[i] = NULL;
		i++;
	}
	free(tab);
	tab = NULL;
}

size_t tab_size(char **tab) {
	size_t size = 0;

	while (tab[size])
		size++;

	return size;
}

void free_exec_struct(t_exec *exec) {
	if (exec->cmd)
		free(exec->cmd);
	if (exec->absolute_path)
		free(exec->absolute_path);
	if (exec->args)
		free_tab(exec->args);
	// if (exec->syscall_names)
	// 	free_tab(exec->syscall_names);
} 

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

void debug_syscall(t_syscall *syscall) {
    if (!syscall) {
        printf("Syscall structure is NULL\n");
        return;
    }

    printf("Syscall Debug Information:\n");
    printf("  Number: %d\n", syscall->num);
    printf("  Name: %s\n", syscall->name ? syscall->name : "NULL");
    printf("  Argument Count: %d\n", syscall->arg_count);

    printf("  Argument Types:\n");
    for (int i = 0; i < 6; i++) {
        if (syscall->arg_types[i]) {
            printf("    [%d]: %s\n", i, syscall->arg_types[i]);
        } else {
            printf("    [%d]: NULL\n", i);
        }
    }

    printf("  Return Type: %s\n", syscall->ret_type ? syscall->ret_type : "NULL");
    printf("\n");
}

bool is_read_syscall(int syscall_num) {
    int read_syscall_numbers[] = {0, 17, 19, 89, 267, 327, 3, 85, 180, 305};

    for (int i = 0; i <= 10; i++) {
        if (syscall_num == read_syscall_numbers[i]) {
			read_syscall = true;
            return true;
        }
    }
    return false;
}