#include "../inc/ft_strace.h"

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

//  cat /usr/include/*/*.h | grep SI_ ==> savoir le define de si_code
void handle_sig(int signum, pid_t pid) {
    siginfo_t siginfo;

    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
        if (signum == SIGINT)
            fprintf(stderr, "ft_strace: Process %d detached\n", pid);
        else
            perror("ptrace getsiginfo");
        return ;
    }

    if (signum == SIGINT) {
        fprintf(stderr, "^C--- SIGINT {si_signo=SIGINT, si_code=%d} ---\n", siginfo.si_code);
        kill(pid, SIGINT);
        fprintf(stderr, "ft_strace: Process %d detached\n", pid);
    } else if (signum == SIGWINCH) {
        fprintf(stdout, "--- SIGWINCH {si_signo=SIGWINCH, si_code=%d, si_pid=%d, si_uid=%d} ---\n", siginfo.si_code, siginfo.si_pid, siginfo.si_uid);
    } else if (signum == SIGCHLD) {
        fprintf(stdout, "--- SIGCHLD {si_signo=SIGCHLD, si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%ld, si_stime=%ld} ---\n",
        siginfo.si_code, siginfo.si_pid, siginfo.si_uid, siginfo.si_status, siginfo.si_utime, siginfo.si_stime);
    }
}