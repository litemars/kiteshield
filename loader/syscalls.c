#include "loader/include/syscalls.h"
#include "loader/include/types.h"

ssize_t sys_write(int fd, const char *s, size_t count)
{
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)s;
    register long x2 asm("x2") = count;
    register long x8 asm("x8") = 64; // __NR_write for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

ssize_t sys_read(int fd, void *buf, size_t count)
{
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = count;
    register long x8 asm("x8") = 63; // __NR_read for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = offset;
    register long x2 asm("x2") = whence;
    register long x8 asm("x8") = 62; // __NR_lseek for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

int sys_open(const char *pathname, int flags, int mode)
{
    register long x0 asm("x0") = (long)pathname;
    register long x1 asm("x1") = flags;
    register long x2 asm("x2") = mode;
    register long x3 asm("x3");
    register long x8 asm("x8") = 56; // __NR_openat for ARM64 (openat, dirfd=AT_FDCWD)
    asm volatile("mov %x3, %x2\n\tmov %x2, %x1\n\tmov %x1, %x0\n\tmov %x0, -100\n\tsvc #0"
                 : "+r"(x0), "=r"(x3), "+r"(x2), "+r"(x1)
                 : "r"(x8)
                 : "memory");
    return x0;
}

int sys_close(int fd)
{
    register long x0 asm("x0") = fd;
    register long x8 asm("x8") = 57; // __NR_close for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

void sys_exit(int status)
{
    register long x0 asm("x0") = status;
    register long x8 asm("x8") = 93; // __NR_exit for ARM64
    asm volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
    while(1) {}
}

void *sys_mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    register long x0 asm("x0") = (long)addr;
    register long x1 asm("x1") = length;
    register long x2 asm("x2") = prot;
    register long x3 asm("x3") = flags;
    register long x4 asm("x4") = fd;
    register long x5 asm("x5") = offset;
    register long x8 asm("x8") = 222; // __NR_mmap for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
    return (void *)x0;
}

int sys_munmap(
    void *addr,
    size_t length)
{
    register long x0 asm("x0") = (long)addr;
    register long x1 asm("x1") = length;
    register long x8 asm("x8") = 215; // __NR_munmap for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
    register long x0 asm("x0") = (long)addr;
    register long x1 asm("x1") = len;
    register long x2 asm("x2") = prot;
    register long x8 asm("x8") = 226; // __NR_mprotect for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

long sys_ptrace(
    enum __ptrace_request request,
    pid_t pid,
    void *addr,
    void *data)
{
    register long x0 asm("x0") = request;
    register long x1 asm("x1") = pid;
    register long x2 asm("x2") = (long)addr;
    register long x3 asm("x3") = (long)data;
    register long x8 asm("x8") = 117; // __NR_ptrace for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

pid_t sys_wait4(pid_t pid, int *wstatus, int options)
{
    register long x0 asm("x0") = pid;
    register long x1 asm("x1") = (long)wstatus;
    register long x2 asm("x2") = options;
    register long x3 asm("x3") = 0; // rusage = NULL
    register long x8 asm("x8") = 260; // __NR_wait4 for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

pid_t sys_fork()
{
    register long x8 asm("x8") = 220; // __NR_clone for ARM64 (fork is clone with special args)
    register long x0 asm("x0") = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000 | 0x00100000 | 0x00200000 | 0x00400000 | 0x00800000 | 0x01000000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x80000000; // CLONE flags (set as needed)
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

int sys_kill(pid_t pid, int sig)
{
    register long x0 asm("x0") = pid;
    register long x1 asm("x1") = sig;
    register long x8 asm("x8") = 129; // __NR_kill for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}

int sys_tgkill(pid_t tgid, pid_t tid, int sig)
{
    register long x0 asm("x0") = tgid;
    register long x1 asm("x1") = tid;
    register long x2 asm("x2") = sig;
    register long x8 asm("x8") = 131; // __NR_tgkill for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

pid_t sys_getpid()
{
    register long x8 asm("x8") = 172; // __NR_getpid for ARM64
    register long x0 asm("x0");
    asm volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}

int sys_rt_sigaction(
    int sig,
    const struct kernel_sigaction *act,
    const struct kernel_sigaction *oact)
{
    register long x0 asm("x0") = sig;
    register long x1 asm("x1") = (long)act;
    register long x2 asm("x2") = (long)oact;
    register long x3 asm("x3") = sizeof(act->sa_mask);
    register long x8 asm("x8") = 134; // __NR_rt_sigaction for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

int sys_prctl(
    int option,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5)
{
    register long x0 asm("x0") = option;
    register long x1 asm("x1") = arg2;
    register long x2 asm("x2") = arg3;
    register long x3 asm("x3") = arg4;
    register long x4 asm("x4") = arg5;
    register long x8 asm("x8") = 167; // __NR_prctl for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

int sys_stat(const char *pathname, struct stat *statbuf)
{
    register long x0 asm("x0") = (long)pathname;
    register long x1 asm("x1") = (long)statbuf;
    register long x2 asm("x2") = 0;
    register long x8 asm("x8") = 1038; // __NR_newfstatat for ARM64 (fstatat)
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

int sys_setrlimit(int resource, struct rlimit *rlim)
{
    register long x0 asm("x0") = resource;
    register long x1 asm("x1") = (long)rlim;
    register long x2 asm("x2") = 0;
    register long x8 asm("x8") = 164; // __NR_prlimit64 for ARM64
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

