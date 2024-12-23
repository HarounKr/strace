#include "../inc/ft_strace.h"

char *get_absolute_path(const char *cmd) {

    char *env_path = getenv("PATH");
    char *absolute_path;
    bool path_found = false;

    if (env_path) {
        char **split_path = ft_split(env_path, ':');
        for (int i = 0; split_path[i]; i++) {
            char *prefix_path = ft_strjoin(split_path[i], "/");
            char *path_to_test = ft_strjoin(prefix_path, cmd);
            if (!access(path_to_test, F_OK)) {
                absolute_path = strdup(path_to_test);
                path_found = true;
            }
            free(prefix_path);
            free(path_to_test);
        }
        free_tab(split_path);
    }
    if (!path_found) {
        absolute_path = calloc(4096, sizeof(char ));
        if (!absolute_path) {
            perror("calloc");
            exit(EXIT_FAILURE);
        }
        if (!realpath(cmd, absolute_path)) {
            perror("ft_strace");
            free(absolute_path);
            exit(EXIT_FAILURE);
        }
    }
    return absolute_path;
}
