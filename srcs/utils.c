#include "../inc/ft_strace.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	size_t	i;
	size_t	b;
	char	*new;

	i = -1;
	b = start;
	if (!s)
		return (NULL);
	if (start > strlen(s))
		return (strdup(""));
	while (s[b] && ++i < len)
		b++;
	new = calloc(sizeof(*new), i + 1);
	if (!new)
		return (NULL);
	i = 0;
	while (s[start] && i < len)
	{
		new[i] = s[start];
		i++;
		start++;
	}
	new[i] = '\0';
	return (new);
}

char	*ft_strjoin(char const *s1, char const *s2)
{
	size_t		i;
	size_t		len_s2;
	char		*dest;

	if (!s1 || !s2)
		return (NULL);
	i = strlen(s1);
	len_s2 = strlen(s2);
	dest = malloc(sizeof(char) * (i + len_s2 + 1));
	if (!dest)
		return (NULL);
	i = -1;
	while (s1[++i])
		dest[i] = s1[i];
	len_s2 = -1;
	while (s2[++len_s2])
	{
		dest[i] = s2[len_s2];
		i++;
	}
	dest[i] = '\0';
	return (dest);
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

void free_exec_struct(t_exec executable) {
	if (executable.cmd)
		free(executable.cmd);
	if (executable.absolute_path)
		free(executable.absolute_path);
	if (executable.args)
		free_tab(executable.args);
	if (executable.envp)
		free_tab(executable.envp);
} 