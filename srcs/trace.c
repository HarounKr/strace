#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 

int trace_exec(t_exec executable) {

    int status;
    pid_t is_child;
    bool alive = true;
    is_child = fork();
    if (!is_child) { 
        ptrace(PTRACE_TRACEME);
        pid_t child_pid = getpid();
        kill(child_pid, SIGSTOP);
        if (execve(executable.absolute_path, executable.args, executable.envp) == -1)
            exit(EXIT_FAILURE);
    }

    wait(&status);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            printf("ça rentre dans les options\n ");
        int options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD |
                     PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;
        ptrace(PTRACE_SETOPTIONS, is_child, NULL, options);
        ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
    } 
    while (alive) {
        struct user_regs_struct regs;
        struct iovec io;

        io.iov_base = &regs;
        io.iov_len = sizeof(regs);

        wait(&status);
        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("Exit code : %d\n ", exit_code);
            alive = false;
        }
        if (WIFSIGNALED(status)) {
            int sig_num = WTERMSIG(status);
            printf("Le fils a été terminé avec le signal : %d\n ", sig_num);
        }
        if ((status >> 8) == (SIGTRAP | 0x80)) { // SIGTRAP | 0x80 = 133
            //printf("Appel système intercepté !\n");
            ptrace(PTRACE_GETREGSET, is_child, (void *)NT_PRSTATUS,&io);
            unsigned long syscall_num = regs.orig_rax;
            // lire aussi les registres pour obtenir les adresses des arguments (rdi, rsi, rdx)
            printf("Syscall num : %ld\n ", syscall_num );
            printf("Syscall name : %s\n ", syscall_names[syscall_num] );
        }
        else if (WIFSTOPPED(status)) {
            int sig_num = WSTOPSIG(status);
            printf("Le fils a été stopé avec le signal : %d\n ", sig_num);
        }
        ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
    } 
    return 0;
}