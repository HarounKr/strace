#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#define TEMP_FILE "temp_syscall_test.txt"

void perform_syscalls() {
    int fd;
    char buffer[128];
    pid_t pid;
    struct stat statbuf;
    time_t current_time;
    current_time = time(NULL);
    printf("Current time: %s", ctime(&current_time));

    fd = open(TEMP_FILE, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    const char *data = "This is a test string for syscalls.\n";
    if (write(fd, data, strlen(data)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);

    fd = open(TEMP_FILE, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read == -1) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }
    buffer[bytes_read] = '\0';
    printf("Data read from file: %s", buffer);

    if (fstat(fd, &statbuf) == -1) {
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }
    printf("File size: %ld bytes\n", statbuf.st_size);

    close(fd);

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        printf("Child process PID: %d\n", getpid());

        execlp("ls", "ls", "-l", NULL);

        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        printf("Parent process waiting for child (PID: %d)\n", pid);

        wait(NULL);
        printf("Child process finished.\n");
    }

    if (unlink(TEMP_FILE) == -1) {
        perror("unlink");
        exit(EXIT_FAILURE);
    }

    if (getcwd(buffer, sizeof(buffer)) == NULL) {
        perror("getcwd");
        exit(EXIT_FAILURE);
    }
    printf("Current working directory: %s\n", buffer);
}

int main() {
    printf("Starting syscall program...\n");
    perform_syscalls();
    printf("Finished syscall program.\n");
    return 0;
}