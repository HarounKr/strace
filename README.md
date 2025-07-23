# strace

## Description

Ce projet a pour objectif de **reproduire le comportement de l'outil `strace`**, qui permet de tracer les **appels système** effectués par un programme en cours d'exécution.

Il est développé en **C** et repose principalement sur l'utilisation de **`ptrace`**, une fonction système qui permet à un processus (le traceur) d'observer et de contrôler l'exécution d'un autre (le tracé).

## À quoi sert `strace` ?

`strace` est un outil essentiel en environnement Unix/Linux, utilisé principalement pour :

- **Déboguer un programme** : voir quels appels système sont effectués, à quel moment, et avec quels arguments.
- **Comprendre le comportement d’un binaire** sans avoir accès au code source.
- **Diagnostiquer des erreurs** liées aux accès fichiers, permissions, segmentation faults, etc.
- **Observer les interactions système** : ouverture de fichiers, allocation mémoire, appels réseau, etc.

## Fonctionnalités implémentées

- Détection de l’architecture du binaire (**32 bits ou 64 bits**)
- Lecture des **registres** pour récupérer les appels système selon l’architecture
- **Affichage du nom de l’appel système**, des **arguments** (convertis selon leur type : `int`, `char *`, etc.) et de la **valeur de retour**
- Lecture directe de la mémoire du processus via **`/proc/[pid]/mem`** pour extraire les **valeurs des arguments**
- Prise en charge de nombreux rous les appels système
- **Gestion des signaux** reçus par le processus tracé

## Utilisation
** Cloner le repo **

Compilation :

```bash
make
```

Exécution :

```bash
./ft_strace tests/many_syscalls64
```

Sortie :

```bash
set_robust_list(0x7ce08b0bea20, 24) =  0
execve("tests/many_syscalls64", ["tests/many_syscalls64"], ["0x7ffd21c86fc0 /* 56 vars */"]) =  0
brk((nil)) =  0x577adeb27000
arch_prctl(12289, 0x7ffc60cee5a0) =  -22
mmap((nil), 8192, 3, 34, -1, 0) =  0x741648cd7000
access("/etc/ld.so.preload", 4) =  -2
openat(-100, "/etc/ld.so.cache", 524288) =  3
newfstatat(3, "", 0x7ffc60ced6f0, 4096) =  0
mmap((nil), 70811, 1, 2, 3, 0) =  0x741648cc5000
close(3) =  0
openat(-100, "/lib/x86_64-linux-gnu/libc.so.6", 524288) =  3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0@\0\0\0\0\0\0\0"..., 832) =  832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\20\3\0\0\0\0\0\0"..., 784, 64) =  784
pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0\2\200\0\300\4\0\0\0"..., 48, 848) =  48
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\315A\13q\17\17\tLh2\355\331Y1\0m\210:\364\216\4\0\0\0"..., 68, 896) =  68
newfstatat(3, "", 0x7ffc60ced7c0, 4096) =  0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\20\3\0\0\0\0\0\0"..., 784, 64) =  784
mmap((nil), 2264656, 1, 2050, 3, 0) =  0x741648a00000
mprotect(0x741648a28000, 2023424, 0) =  0
mmap(0x741648a28000, 1658880, 5, 2066, 3, 163840) =  0x741648a28000
mmap(0x741648bbd000, 360448, 1, 2066, 3, 1822720) =  0x741648bbd000
mmap(0x741648c16000, 24576, 3, 2066, 3, 2183168) =  0x741648c16000
mmap(0x741648c1c000, 52816, 3, 50, -1, 0) =  0x741648c1c000
close(3) =  0
mmap((nil), 12288, 3, 34, -1, 0) =  0x741648cc2000
arch_prctl(4098, 0x741648cc2740) =  0
set_tid_address(0x741648cc2a10) =  6600
set_robust_list(0x741648cc2a20, 24) =  0
rseq(0x741648cc30e0, 0x20, 0, 0x53053053) =  0
mprotect(0x741648c16000, 16384, 1) =  0
mprotect(0x577aaedbe000, 4096, 1) =  0
mprotect(0x741648d11000, 8192, 1) =  0
prlimit64(0, 3, (nil), 0x7ffc60cee300) =  0
munmap(0x741648cc5000, 70811) =  0
newfstatat(1, "", 0x7ffc60cee4c0, 4096) =  0
getrandom(0x741648c214d8, 8, 1) =  8
brk((nil)) =  0x577adeb27000
brk(0x577adeb48000) =  0x577adeb48000
write(1, "Starting syscall-intensive program...
Starting syscall-intensive program...
", 38) =  38
openat(-100, "/etc/localtime", 524288) =  3
newfstatat(3, "", 0x7ffc60cee390, 4096) =  0
newfstatat(3, "", 0x7ffc60cee1b0, 4096) =  0
read(3, "TZif2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\15\0\0\0\15\0\0\0\0\0\0\0\270\0\0\0\15"..., 4096) =  2962
lseek(3, -1863, 1) =  1099
read(3, "TZif2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\15\0\0\0\15\0\0\0\0\0\0\0\270\0\0\0\15"..., 4096) =  1863
close(3) =  0
write(1, "Current time: Wed Jul 23 10:53:02 2025
Current time: Wed Jul 23 10:53:02 2025
", 39) =  39
openat(-100, "temp_syscall_test.txt", 577) =  3
write(3, "This is a test string for syscalls.
", 36) =  36
close(3) =  0
openat(-100, "temp_syscall_test.txt", 0) =  3
read(3, "This is a test string for syscalls.\n\26t\0\0"..., 127) =  36
write(1, "Data read from file: This is a test string for syscalls.
Data read from file: This is a test string for syscalls.
", 57) =  57
newfstatat(3, "", 0x7ffc60cee520, 4096) =  0
write(1, "File size: 36 bytes
 This is a test string for syscalls.
File size: 36 bytes
", 20) =  20
close(3) =  0
Child process PID: 6601
clone(0x1200011, (nil), 0) =  6601
write(1, "Parent process waiting for child (PID: 6601)
r syscalls.
Parent process waiting for child (PID: 6601)
", 45) =  45
total 228
-rwxrwxr-x 1 hkrifa hkrifa 198472 juil. 23 10:52 ft_strace
drwxrwxr-x 2 hkrifa hkrifa   4096 juil. 23 10:28 gen
drwxrwxr-x 2 hkrifa hkrifa   4096 juil. 23 10:28 inc
-rw-rw-r-- 1 hkrifa hkrifa    790 juil. 23 10:28 Makefile
drwxrwxr-x 2 hkrifa hkrifa   4096 juil. 23 10:52 objs
-rw-rw-r-- 1 hkrifa hkrifa   1615 juil. 23 10:52 README.md
drwxrwxr-x 2 hkrifa hkrifa   4096 juil. 23 10:28 srcs
-rw------- 1 hkrifa hkrifa     36 juil. 23 10:53 temp_syscall_test.txt
drwxrwxr-x 2 hkrifa hkrifa   4096 juil. 23 10:28 tests
wait4(-1, (nil), 0, (nil)) =  6601
--- SIGCHLD {si_signo=SIGCHLD, si_code=1, si_pid=6601, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
write(1, "Child process finished.
or child (PID: 6601)
r syscalls.
Child process finished.
", 24) =  24
unlink("temp_syscall_test.txt") =  0
getcwd("This is a test string for syscalls.
", 128) =  27
write(1, "Current working directory: /home/hkrifa/Bureau/strace
s.
Current working directory: /home/hkrifa/Bureau/strace
", 54) =  54
write(1, "Finished syscall-intensive program.
ifa/Bureau/strace
s.
Finished syscall-intensive program.
", 36) =  36
exit_group(0) =  ?
+++ exited with 0 +++
```