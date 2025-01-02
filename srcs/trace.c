#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 
// https://man7.org/linux/man-pages/man2/ptrace.2.html
// https://man7.org/linux/man-pages/man2/process_vm_readv.2.html


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
                user_regs_struct regs;
                iovec io;

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
                // lire aussi les registres pour obtenir les adresses des arguments (rdi, rsi, rdx, rax)
                    unsigned long syscall_num = regs.orig_rax;
                    for (int i = 0; syscalls[i].name != NULL; i++) {
                        if (!strcmp(syscalls[i].name, syscall_names[syscall_num])) {
                            int n_args = syscalls[i].arg_count;
                            // Entrée d'un syscall
                            if (is_preexit) {
                                    format_output(regs, n_args, i, is_child);
                                    if (!strncmp(syscalls[i].name, "exit", strlen("exit")))
                                        fprintf(stdout, "?\n");
                                }
                            // Sortie d'un syscall
                            else {
                                printf("%llx\n", regs.rax);
                            }
                        }
                    }
                    is_preexit = !is_preexit;
                } 
                else if (WIFSTOPPED(status)) {
                   //int sig_num = WSTOPSIG(status);
                   //printf("Le fils a été stopé avec le signal : %d\n ", sig_num);
                }
                ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
                i++;
            } 
    }
    return exit_code;
} 