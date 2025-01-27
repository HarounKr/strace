#include "../inc/ft_strace.h"
uint64_t *regs_addr = NULL;
// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall

static int sigint_received = 0;

static void handle_sigint(int sig) {
    sigint_received = sig;
}

static void install_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

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


void child_proc(t_exec *exec) {
    if (execve(exec->absolute_path, exec->args, exec->envp) < 0)
        perror("execve");
    exit(EXIT_FAILURE);
}

int ptrace_init(pid_t pid) {

    if (ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
            perror("ptrace seize");
            return -1;
    }
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
            perror("ptrace seize");
            return -1;
    }
    return 0;
}

static t_syscall *syscall_matches(unsigned long reg_syscall_num, t_syscall syscalls[]) {
    
    for (int i = 0; syscalls[i].name != NULL;  i++) {
        if ((unsigned long) syscalls[i].num == reg_syscall_num)
            return &syscalls[i];
    }
    return NULL;
}

int is_syscall(pid_t pid, union x86_regs_union *regs_t, struct iovec *io, bool *is_preexit) {
    memset(regs_t, 0, sizeof(union x86_regs_union));
    io->iov_base = regs_t;
    io->iov_len = sizeof(union x86_regs_union);

    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, io) == -1) {
        perror("PTRACE_GETREGSET");
        fprintf(stderr, "iov_len final=%zu\n", io->iov_len);
        return -1;
    }

    bool is_64;
    if (io->iov_len == sizeof(struct user_regs_struct)) {
        is_64 = true;
    } else if (io->iov_len == sizeof(struct i386_user_regs_struct)) {
        is_64 = false;
    } else {
        fprintf(stderr, "exec type none recognized\n");
        return -1;
    }

    unsigned long reg_syscall_num = is_64 ? regs_t->regs64.orig_rax : regs_t->regs32.orig_eax;
    t_syscall *syscall = syscall_matches(reg_syscall_num, is_64 ? syscalls64 : syscalls32);
    if (syscall) {
        int n_args = syscall->arg_count;
        if (*is_preexit) {
            regs_addr = get_regs_addr(regs_t, is_64);
            if (!regs_addr)
                return -1;
            if (is_read_syscall(syscall->num) == false) { 
                print_args(regs_addr, n_args, syscall, pid);
                if (!strncmp(syscall->name, "exit", strlen("exit"))) {
                    free(regs_addr);
                    regs_addr = NULL;
                    fprintf(stdout, "?\n");
                }
            }
        } else {
            
            if (is_read_syscall(syscall->num)) {
                print_args(regs_addr, n_args, syscall, pid);
            }
            if (regs_addr) {
                free(regs_addr);
                regs_addr = NULL;
            }
            uint64_t ret_value = is_64 ? regs_t->regs64.rax : regs_t->regs32.eax;
            print_ret_value(ret_value, syscall->ret_type);
        }
        *is_preexit = !(*is_preexit);
    }
    return 0;
}


int trace_exec(t_exec *exec) {
    int status;
    int exit_code = 0;
    bool is_alive = true;
    bool is_preexit = true;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        child_proc(exec);
    } else {
        union x86_regs_union regs_t;
        struct iovec io;
        install_signal_handler();
        if (ptrace_init(pid) == -1) {
            return -1;
        }
        while (is_alive) {
            read_syscall = false;
            sigset_empty();
            waitpid(pid, &status, WUNTRACED);
            sigset_blocked();
            if (sigint_received == SIGINT) {
                handle_sig(SIGINT, pid);
                is_alive = false;
            }
            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
                fprintf(stdout, "+++ exited with %d +++\n", exit_code);
                is_alive = false;
            } else if (WIFSIGNALED(status)) {
                int sig_num = WTERMSIG(status);
                printf("Le fils s'est terminé avec le signal : %d\n", sig_num);
                is_alive = false;
            } else if (WIFSTOPPED(status)) {
                int stop_signal = WSTOPSIG(status);
                if (stop_signal == SIGWINCH) {
                    handle_sig(SIGWINCH, pid);
                } else if (stop_signal == SIGCHLD) {
                    handle_sig(SIGCHLD, pid);
                }
                else if (stop_signal == SIGSEGV) {
                    fprintf(stderr, "+++ killed by SIGSEGV (core dumped) +++\n");
                    sleep(1);
                    fprintf(stderr, "Segmentation fault (core dumped)\n");
                    is_alive = false;
                } else if (stop_signal == (SIGTRAP | 0x80)) {
                        if (is_syscall(pid, &regs_t, &io, &is_preexit) == -1) {
                            fprintf(stderr, "ft_strace: Erreur lors du traitement d'un syscall\n");
                            return -1;
                        }
                }
            } 
            if (is_alive) {
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }
        }
    }
    return exit_code;
}