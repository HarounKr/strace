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
    unsigned long i = 0;
    char **doubleptr = NULL;

    while (is_alive) {
        unsigned long ptr_value = peekptr(pid, addr + i * sizeof(ptr_value));
        if (ptr_value == 0 || (long) ptr_value == -1)
            break;
        i++;
    }
    if (i > 10) {
        doubleptr = calloc(2, sizeof(char *));
        printf(" ici ?");
        char buf[256];
        snprintf(buf, 256, "%lx /* %d vars */", addr, (int) i);
        doubleptr[0] = strdup(buf); 
    }
    else {
        doubleptr = calloc(i + 1, sizeof(char *));
        i = 0;
        while (is_alive) {
            unsigned long ptr_value = peekptr(pid, addr + i * sizeof(ptr_value));
            if (ptr_value == 0 || (long) ptr_value == -1)
                break;
            char *str = peekstr(pid, ptr_value);
            if (str == NULL) {
                free(str);
                break ;
            }
            doubleptr[i] = str;
            i++;
        }
    }
    return  doubleptr;
}

int trace_exec(t_exec executable) {

    int status;
    int exit_code = 0;
    pid_t is_child;
    bool is_alive = true;
    bool is_preexit = true;
    is_child = fork();
    int i = 0;

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
                    exit_code = WEXITSTATUS(status);
                    //printf("Exit code : %d\n ", exit_code);
                    free_tab(syscall_names);
                    return exit_code;
                }
                if (WIFSIGNALED(status)) {
                    //int sig_num = WTERMSIG(status);
                    
                    //printf("Le fils a été terminé avec le signal : %d\n ", sig_num);
                }
                if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)){ // SIGTRAP | 0x80 = 133
                    //printf("Appel système intercepté !\n");
                    ptrace(PTRACE_GETREGSET, is_child, (void *)NT_PRSTATUS,&io );
                   unsigned long syscall_num = regs.orig_rax;
                
                    if (is_preexit) { // Entrée d'un syscall
                        printf("%s\n ", syscall_names[syscall_num] );
                        is_preexit = ! is_preexit;
                        if (!strcmp(syscall_names[regs.orig_rax], "execve")){
                            char *arg1 = peekstr(is_child, regs.rdi);
                            char **rsi = peekdoubleptr(is_child, regs.rdx);
                            char *arg2 = to_string(rsi);
                            fprintf(stdout, "%s(\"%s\", %s)\n", syscall_names[syscall_num], arg1, arg2);
                            free_tab(rsi);

                        } 
                    } else { // Sortie d'un syscall
                        is_preexit = ! is_preexit;
                        //printf("rax: %lld\n", regs.rax);
                    }
                } 
                    // lire aussi les registres pour obtenir les adresses des arguments (rdi, rsi, rdx, rax)
                    //printf("Syscall num : %ld rdi: %lld rsi: %lld rdx: %lld\n ", syscall_num, regs.rdi, regs.rsi, regs.rdx);
                else if (WIFSTOPPED(status)) {
                   //int sig_num = WSTOPSIG(status);
                   //printf("Le fils a été stopé avec le signal : %d\n ", sig_num);
                }
                if (i <= 1)
                    ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
                i++;
            } 
    }
    return exit_code;
} 