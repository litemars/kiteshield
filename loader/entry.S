.section .text
.global _start

_start:
    // On AArch64, x0-x7 are argument registers, x29 is fp, x30 is lr
    mov x29, xzr        // Zero frame pointer
    mov x0, sp          // Pass stack pointer as entry_stacktop to load

#ifdef USE_RUNTIME
    bl do_fork          // Call do_fork (returns only in child)
#endif

    bl load             // Call load(entry_stacktop)
    mov x19, x0         // Save return value (ld.so entry point) in x19

#ifdef USE_RUNTIME
    bl child_start_ptrace
#endif

    // Zero non-privileged registers (not strictly necessary, but for determinism)
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    mov x18, xzr
    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x23, xzr
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x30, xzr

    br x19              // Jump to ld.so entry point
