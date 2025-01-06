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
}

size_t tab_size(char **tab) {
	size_t size = 0;

	while (tab[size])
		size++;

	return size;
}

void free_exec_struct(t_exec executable) {
	if (executable.cmd)
		free(executable.cmd);
	if (executable.absolute_path)
		free(executable.absolute_path);
	if (executable.args)
		free_tab(executable.args);
	if (executable.syscall_names)
		free_tab(executable.syscall_names);
} 