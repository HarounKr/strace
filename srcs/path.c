#include "../inc/ft_strace.h"

char *get_absolute_path(const char *cmd) {

    char *env_path = getenv("PATH");
    char *absolute_path;
    bool path_found = false;

    if (env_path) {
        char **split_path = ft_split(env_path, ':');
        for (int i = 0; split_path[i]; i++) {
            char path_to_test[256];
            snprintf(path_to_test, 256, "%s/%s", split_path[i], cmd);
            if (!access(path_to_test, F_OK)) {
                absolute_path = strdup(path_to_test);
                path_found = true;
                break;
            }
        }
        free_tab(split_path);
    }
    if (!path_found) {
        char **temp = ft_split(cmd, ' ');
        absolute_path = strdup(temp[0]);
        free_tab(temp);
    }
        
    return absolute_path;
}
