#include "../inc/ft_strace.h"

// /usr/include/x86_64-linux-gnu/asm/unistd_64.h ==> valeurs des syscall 
// https://man7.org/linux/man-pages/man2/ptrace.2.html
// https://man7.org/linux/man-pages/man2/process_vm_readv.2.html

static long long int *get_regs_addr(t_unified_regs reg_t, t_exec executable) {
    long long int *regs_addr = calloc(sizeof(long long int), 6);
    if (!regs_addr) {
        perror("calloc ");
        return NULL;
    }
   // ARG0 (rdi)	ARG1 (rsi)	ARG2 (rdx)	ARG3 (r10)	ARG4 (r8)	ARG5 (r9)
    if (executable.elf_type == 64) {
        regs_addr[0] = (unsigned long long) reg_t.regs64.rdi;
        regs_addr[1] = (unsigned long long) reg_t.regs64.rsi;
        regs_addr[2] = (unsigned long long) reg_t.regs64.rdx;
        regs_addr[3] = (unsigned long long) reg_t.regs64.r10;
        regs_addr[4] = (unsigned long long) reg_t.regs64.r8;
        regs_addr[5] = (unsigned long long) reg_t.regs64.r9;
    // ARG0 (ebx)	ARG1 (ecx)	ARG2 (edx)	ARG3 (esi)	ARG4 (edi)	ARG5 (ebp)
    } else {
        regs_addr[0] = (long) reg_t.regs32.ebx;
        regs_addr[1] = (long) reg_t.regs32.ecx;
        regs_addr[2] = (long) reg_t.regs32.edx;
        regs_addr[3] = (long) reg_t.regs32.esi;
        regs_addr[4] = (long) reg_t.regs32.edi;
        regs_addr[5] = (long) reg_t.regs32.ebp;
    }
    return regs_addr;
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
        t_unified_regs regs_t;
        iovec io;

        while (is_alive) {
            if (executable.elf_type == 64) {
                io.iov_base = &regs_t.regs64;
                io.iov_len = sizeof(regs_t.regs64);
            } else {
                io.iov_base = &regs_t.regs32;
                io.iov_len = sizeof(regs_t.regs32);
            }
            wait(&status);
            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
                fprintf(stdout, "+++ exited with %d +++\n", exit_code);
                return exit_code;
            }
            if (WIFSIGNALED(status)) {
                //int sig_num = WTERMSIG(status);
                
                //printf("Le fils a été terminé avec le signal : %d\n ", sig_num);
            }
            if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)){ // SIGTRAP | 0x80 = 133
                ptrace(PTRACE_GETREGSET, is_child, (void *)NT_PRSTATUS,&io);
                unsigned long syscall_num = 0;
                if (executable.elf_type == 64)
                    syscall_num = regs_t.regs64.orig_rax;
                else
                    syscall_num = regs_t.regs32.orig_eax;
                //printf("%d\n",(int) regs_t.regs32.orig_eax);
                for (int i = 0; syscalls[i].name != NULL; i++) {
                    if (!strcmp(syscalls[i].name, executable.syscall_names[syscall_num])) {
                        int n_args = syscalls[i].arg_count;
                        // Entrée d'un syscall
                        if (is_preexit) {
                            long long int *regs_addr = get_regs_addr(regs_t, executable);
                            
                            format_output(regs_addr, n_args, i, is_child);
                            if (!strncmp(syscalls[i].name, "exit", strlen("exit")))
                                fprintf(stdout, "?\n");
                            free(regs_addr);
                        }
                        // Sortie d'un syscall
                        else {
                            long long int ret_value = 0;
                            if (executable.elf_type == 64)
                                ret_value = regs_t.regs64.rax;
                            else
                                ret_value = regs_t.regs32.eax;
                            if (!strcmp(syscalls[i].ret_type, "int")) {
                                fprintf(stdout, "%d\n", (int)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "unsigned int")) {
                                fprintf(stdout, "%u\n", (unsigned int)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "void*")) {
                                fprintf(stdout, "%p\n", (void *)ret_value);
                            } else if (!strcmp(syscalls[i].ret_type, "long")) {
                                fprintf(stdout, "%ld\n", (long) ret_value);
                            }  else {
                                fprintf(stdout,"%lld\n", ret_value);
                            }
                        }
                    }
                }
                is_preexit = !is_preexit;
            } 
            ptrace(PTRACE_SYSCALL, is_child, NULL, NULL);
            i++;
        }
    }
    return exit_code;
}