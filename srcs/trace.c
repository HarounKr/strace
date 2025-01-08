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

void child_proc(t_exec *exec) {
    raise(SIGSTOP);
    if (execve(exec->absolute_path, exec->args, exec->envp) < 0) {
        perror("execve");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_FAILURE);
}

int ptrace_init(pid_t pid) {
    int status;

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
            perror("ptrace seize");
            return -1;
    }
    sigset_empty();
    waitpid(pid, &status, 0);
    sigset_blocked();

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
            perror("ptrace setoptions");
            return -1;
        }
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace_syscall");
            return -1;
        }
    }
    return 0;
}

int syscall_matches(t_exec *exec, unsigned long syscall_num) {
    int total_syscalls = tab_size(exec->syscall_names);
    
    if ((int) syscall_num < total_syscalls) {
        for (int i = 0; syscalls[i].name != NULL; i++) {
            if (!strcmp(syscalls[i].name, exec->syscall_names[syscall_num]))
                return i;
        }
    }
    return -1;
}


int is_syscall(pid_t pid, t_exec *exec, union x86_regs_union *regs_t, struct iovec *io, bool *is_preexit) {
    memset(regs_t, 0, sizeof(*regs_t));
    io->iov_base = regs_t;
    io->iov_len = sizeof(*regs_t);

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

    unsigned long syscall_num = is_64 ? regs_t->regs64.orig_rax : regs_t->regs32.orig_eax;

    int index = syscall_matches(exec, syscall_num);
    if (index >= 0) {
        int n_args = syscalls[index].arg_count;
        if (*is_preexit) {
            uint64_t *regs_addr = get_regs_addr(regs_t, is_64);
            if (!regs_addr)
                return -1;
            print_args(regs_addr, n_args, index, pid);
            if (!strncmp(syscalls[index].name, "exit", strlen("exit"))) {
                fprintf(stdout, "?\n");
            }
            free(regs_addr);
        } else {
            uint64_t ret_value = is_64 ? regs_t->regs64.rax : regs_t->regs32.eax;
            print_ret_value(ret_value, index);
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
        if (ptrace_init(pid) == -1) {
            return -1;
        }
        while (is_alive) {
            sigset_empty();
            waitpid(pid, &status, 0);
            sigset_blocked();

            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
                fprintf(stdout, "+++ exited with %d +++\n", exit_code);
                is_alive = false;
            } else if (WIFSIGNALED(status)) {
                int sig_num = WTERMSIG(status);
                printf("Le fils s'est terminé avec le signal : %d\n", sig_num);
                is_alive = false;
            } else if (WIFSTOPPED(status)) {
                if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                    if (is_syscall(pid, exec, &regs_t, &io, &is_preexit) == -1) {
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