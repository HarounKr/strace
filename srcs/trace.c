#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 
// https://man7.org/linux/man-pages/man2/ptrace.2.html
// https://man7.org/linux/man-pages/man2/process_vm_readv.2.html


static uint64_t *get_regs_addr(union x86_regs_union *reg_t, bool is_64) {
    uint64_t *regs_addr = calloc(sizeof(long long int), 6);
    if (!regs_addr) {
        perror("calloc ");
        return NULL;
    }
   // ARG0 (rdi)	ARG1 (rsi)	ARG2 (rdx)	ARG3 (r10)	ARG4 (r8)	ARG5 (r9)
    if (is_64) {
        regs_addr[0] = reg_t->regs64.rdi;
        regs_addr[1] = reg_t->regs64.rsi;
        regs_addr[2] = reg_t->regs64.rdx;
        regs_addr[3] = reg_t->regs64.r10;
        regs_addr[4] = reg_t->regs64.r8;
        regs_addr[5] = reg_t->regs64.r9;
    // ARG0 (ebx)	ARG1 (ecx)	ARG2 (edx)	ARG3 (esi)	ARG4 (edi)	ARG5 (ebp)
    } else {
        regs_addr[0] = (uint32_t) reg_t->regs32.ebx;
        regs_addr[1] = (uint32_t) reg_t->regs32.ecx;
        regs_addr[2] = (uint32_t) reg_t->regs32.edx;
        regs_addr[3] = (uint32_t) reg_t->regs32.esi;
        regs_addr[4] = (uint32_t) reg_t->regs32.edi;
        regs_addr[5] = (uint32_t) reg_t->regs32.ebp;
    }
    return regs_addr;
}

void sigset_empty() {
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
}

void sigset_blocked() {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGPIPE);
    sigaddset(&blocked, SIGTERM);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
}

int trace_exec(t_exec executable)
{
    int status;
    int exit_code = 0;
    bool is_preexit = true;
    bool is_alive = true;

    pid_t is_child = fork();
    if (is_child == 0) {
        raise(SIGSTOP);
        if (execve(executable.absolute_path, executable.args, executable.envp) == -1) {
            perror("execve");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_FAILURE);
    }
    else if (is_child < 0) {
        perror("fork");
        return 1;
    }
    else {
        if (ptrace(PTRACE_SEIZE, is_child, NULL, NULL) == -1) {
            perror("ptrace seize");
            return 1;
        }

        sigset_empty();
        waitpid(is_child, &status, WUNTRACED);
        sigset_blocked();

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            ptrace(PTRACE_SETOPTIONS, is_child, NULL, PTRACE_O_TRACESYSGOOD);
            ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
        }

        union x86_regs_union regs_t;
        struct iovec io;

        while (is_alive) {
            sigset_empty();
            wait(&status);
            sigset_blocked();

            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
                fprintf(stdout, "+++ exited with %d +++\n", exit_code);
                return exit_code;
            }
            if (WIFSIGNALED(status)) {
                int sig_num = WTERMSIG(status);
                printf("Le fils s'est terminé avec le signal : %d\n", sig_num);
                return 1;
            }

            /* Vérif si c'est un arrêt sur syscall => SIGTRAP|0x80 = 133 */
            if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {

                memset(&regs_t, 0, sizeof(regs_t));
                io.iov_base = &regs_t;
                io.iov_len  = sizeof(regs_t);

                if (ptrace(PTRACE_GETREGSET, is_child, (void*)NT_PRSTATUS, &io) == -1) {
                    perror("PTRACE_GETREGSET");
                    fprintf(stderr, "iov_len final=%zu\n", io.iov_len);
                    return 1;
                }
                bool is_64 = false;
                if (io.iov_len == sizeof(struct user_regs_struct)) {
                    is_64 = true;
                } else if (io.iov_len == sizeof(struct i386_user_regs_struct)) {
                    is_64 = false;
                } else {
                    fprintf(stderr, "Erreur: iov_len=%zu (inconnu, ni 32 ni 64)\n", io.iov_len);
                    return 1;
                }
                unsigned long syscall_num = 0;
                if (is_64) {
                    syscall_num = regs_t.regs64.orig_rax;
                } else {
                    syscall_num = regs_t.regs32.orig_eax;
                }
                for (int i = 0; syscalls[i].name != NULL; i++) {

                    if (!strcmp(syscalls[i].name, executable.syscall_names[syscall_num])) {
                        int n_args = syscalls[i].arg_count;
                        if (is_preexit) {
                            uint64_t *regs_addr = get_regs_addr(&regs_t, is_64);
                            format_output(regs_addr, n_args, i, is_child);
                            if (!strncmp(syscalls[i].name, "exit", strlen("exit"))) {
                                fprintf(stdout, "?\n");
                            }
                            free(regs_addr);
                        }
                        /* Sortie du syscall */
                        else {
                            uint64_t ret_value = 0;
                            if (is_64) {
                                ret_value = regs_t.regs64.rax;
                            } else {
                                ret_value = regs_t.regs32.eax;
                            }

                            /* Selon le type de retour */
                            if (!strcmp(syscalls[i].ret_type, "int")) {
                                fprintf(stdout, "%d\n", (int)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "unsigned int")) {
                                fprintf(stdout, "%u\n", (unsigned int)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "void*")) {
                                fprintf(stdout, "%p\n", (void *)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "long")) {
                                fprintf(stdout, "%ld\n", (long) ret_value);
                            } else {
                                fprintf(stdout, "%lu\n", ret_value);
                            }
                        }
                    }
                }
                is_preexit = !is_preexit;
            }
            ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
        }
    }
    return exit_code;
}