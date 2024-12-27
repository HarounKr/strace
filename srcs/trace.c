#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 
// https://man7.org/linux/man-pages/man2/ptrace.2.html
// https://man7.org/linux/man-pages/man2/process_vm_readv.2.html


int peekint(unsigned long addr){
    return (int) addr;
}

unsigned long peekptr(pid_t pid, unsigned long addr) {
    if (is_addr_mapped(pid, addr)) {
         unsigned long val;
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return -1;
        }
        off_t pos = lseek(fd, (off_t)addr, SEEK_SET);
        if (pos == -1) {
            close(fd);
            return -1;
        }

        ssize_t n_read = read(fd, &val, sizeof(val));
        if (n_read < 0) {
            close(fd);
            return -1;
        } 
        close(fd);
        return val;
    }
    return -1;
}

char *peekstr(pid_t pid, unsigned long addr) {

    if (is_addr_mapped(pid, addr)) {
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return NULL;
        }
        char *buf = calloc(sizeof(char), 256);
        if (!buf) {
            close(fd);
            return NULL;
        }
        off_t pos = lseek(fd, (off_t)addr, SEEK_SET);
        if (pos == -1) {
            free(buf);
            close(fd);
            return NULL;
        }

        ssize_t n_read = read(fd, buf, 256);
        if (n_read < 0) {
            free(buf);
            close(fd);
            return NULL;
        } 
        buf[n_read] = '\0';

        close(fd);
        return buf;
    }
    return NULL;
}

char **peekdoubleptr(pid_t pid, unsigned long addr) {

    bool is_alive = true;
    unsigned long ptr_value = peekptr(pid, addr);
    char **doubleptr = NULL;

    while (is_alive) {
        char *str = peekstr(pid, ptr_value);
        if (*str == '\0')
            is_alive = false;
        ptr_value += sizeof(ptr_value);
    }
    return  doubleptr;
}

int trace_exec(t_exec executable) {

    int status;
    pid_t is_child;
    bool is_alive = true;
    bool is_preexit = true;
    is_child = fork();

    if (!is_child) {
        if (execve(executable.absolute_path, executable.args, executable.envp) == -1)
            exit(EXIT_FAILURE);
    } else {
            kill(is_child, SIGSTOP);
            waitpid(is_child, &status, WUNTRACED);
            ptrace(PTRACE_SEIZE, is_child, NULL, NULL);
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                int options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT;
                ptrace(PTRACE_SETOPTIONS, is_child, NULL, options);
                ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);

            } 
            while (is_alive) {
                struct user_regs_struct regs;
                struct iovec io;

                io.iov_base = &regs;
                io.iov_len = sizeof(regs);

                wait(&status);
                char **syscall_names = get_syscall_names();
                if (syscall_names == NULL)
                    return 1;
                if (WIFEXITED(status)) {
                    int exit_code = WEXITSTATUS(status);
                    printf("Exit code : %d\n ", exit_code);
                    free_tab(syscall_names);
                    is_alive = false;
                }
                if (WIFSIGNALED(status)) {
                    int sig_num = WTERMSIG(status);
                    printf("Le fils a été terminé avec le signal : %d\n ", sig_num);
                }
                if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)){ // SIGTRAP | 0x80 = 133
                    //printf("Appel système intercepté !\n");
                    ptrace(PTRACE_GETREGSET, is_child, (void *)NT_PRSTATUS,&io );
                    unsigned long syscall_num = regs.orig_rax;
                
                    if (is_preexit) { // Entrée d'un syscall
                        printf("%s\n ", syscall_names[syscall_num] );
                        is_preexit = ! is_preexit;
                        //if (!strcmp(syscall_names[regs.orig_rax], "execve")){
                           // peekdoubleptr(is_child, regs.rsi);
                            printf( "rdi: %s\n", peekstr(is_child, regs.rdi));
                            printf( "rsi: %ld\n", peekptr(is_child, regs.rsi));
                            printf( "rdx: %ld\n", peekptr(is_child, regs.rdx));
                        //} 
                    } else { // Sortie d'un syscall
                        is_preexit = ! is_preexit;
                        printf("rax: %lld\n", regs.rax);
                    }
                } 
                    // lire aussi les registres pour obtenir les adresses des arguments (rdi, rsi, rdx, rax)
                    //printf("Syscall num : %ld rdi: %lld rsi: %lld rdx: %lld\n ", syscall_num, regs.rdi, regs.rsi, regs.rdx);
                else if (WIFSTOPPED(status)) {
                   int sig_num = WSTOPSIG(status);
                   printf("Le fils a été stopé avec le signal : %d\n ", sig_num);
                }
                ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
            } 
    }
    return 0;
} 