#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 
// https://man7.org/linux/man-pages/man2/ptrace.2.html
// https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

int trace_exec(t_exec executable) {

    int status;
    pid_t is_child;
    bool is_alive = true;
    bool is_preexit = true;
    is_child = fork();
    if (!is_child) { 
        ptrace(PTRACE_TRACEME);
        pid_t child_pid = getpid();
        kill(child_pid, SIGSTOP);
        if (execve(executable.absolute_path, executable.args, executable.envp) == -1)
            exit(EXIT_FAILURE);
    } else {
            wait(&status);
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
                    if (is_preexit){
                        printf("Syscall name : %s\n ", syscall_names[syscall_num] );
                        is_preexit = ! is_preexit;
                    } else {
                        is_preexit = ! is_preexit;
                }
                    }
                    // lire aussi les registres pour obtenir les adresses des arguments (rdi, rsi, rdx)
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