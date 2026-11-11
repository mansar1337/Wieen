/*
 * Wieen bootstrap stub.
 *
 * This tiny piece of code is written into a padding hole of the Roblox
 * client image and reached through a detour on one of its functions.  It
 * loads the Wieen agent with dlopen(3) exactly once and then returns; the
 * host restores the original bytes as soon as the agent's socket appears.
 *
 * The data block right after the code is filled in by the injector:
 *
 *   +0x00  absolute path of the agent
 *   +0x08  address of dlopen()
 *   +0x10  address of the patched function (unused, kept for debugging)
 *   +0x18  the original bytes of the patched function
 *   +0x20  the original bytes, upper half
 *   +0x28  "already loaded" flag
 *   +0x29  trace marker
 *   +0x30  probe results (socket, openat, mmap)
 */

    .text
    .type wieen_boot, @function
wieen_boot:
    /* keep the arguments of the function we displaced */
    pushq %rax
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9

    leaq  wieen_boot_data(%rip), %r11

    /* only ever load the agent once */
    cmpb  $0, 0x28(%r11)
    jne   .done

    /* trace marker: the host checks this to see how far we got */
    movb  $0xAA, 0x29(%r11)

#ifdef WIEEN_PROBE
    /* probe which syscalls the sandbox allows; the selector is data[0x50] */
    movq  0x50(%r11), %rcx
    cmpq  $1, %rcx
    je    .p_socket
    cmpq  $2, %rcx
    je    .p_openat
    cmpq  $3, %rcx
    je    .p_mmap
    cmpq  $4, %rcx
    je    .p_getpid
    cmpq  $5, %rcx
    je    .p_write
    cmpq  $6, %rcx
    je    .p_inet
    cmpq  $7, %rcx
    je    .p_inet_dgram
    cmpq  $8, %rcx
    je    .p_futex
    cmpq  $9, %rcx
    je    .p_clock

.p_inet:
    movl  $41, %eax
    movl  $2, %edi           /* AF_INET */
    movl  $1, %esi           /* SOCK_STREAM */
    xorl  %edx, %edx
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_inet_dgram:
    movl  $41, %eax
    movl  $2, %edi           /* AF_INET */
    movl  $2, %esi           /* SOCK_DGRAM */
    xorl  %edx, %edx
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_futex:
    movl  $202, %eax        /* futex */
    movl  $0, %edi
    movl  $0, %esi
    movl  $1, %edx           /* FUTEX_WAKE */
    movl  $0, %r10d
    movl  $0, %r8d
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_clock:
    movl  $228, %eax        /* clock_gettime */
    movl  $0, %edi
    leaq  wieen_boot_data(%rip), %rsi
    xorl  %edx, %edx
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_getpid:
    movl  $39, %eax          /* getpid */
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_write:
    movl  $1, %eax           /* write */
    movl  $2, %edi
    leaq  wieen_boot_path(%rip), %rsi
    movl  $1, %edx
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_socket:
    movl  $41, %eax          /* socket */
    movl  $1, %edi           /* AF_UNIX */
    movl  $1, %esi           /* SOCK_STREAM */
    xorl  %edx, %edx
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_openat:
    movl  $257, %eax         /* openat */
    movl  $-100, %edi
    leaq  wieen_boot_path(%rip), %rsi
    xorl  %edx, %edx
    xorl  %r10d, %r10d
    syscall
    movq  %rax, 0x30(%r11)
    jmp   .probe_done

.p_mmap:
    movl  $9, %eax           /* mmap */
    xorl  %edi, %edi
    movl  $4096, %esi
    movl  $7, %edx           /* PROT_READ|WRITE|EXEC */
    movl  $0x32, %r10d       /* MAP_PRIVATE|MAP_ANONYMOUS */
    movl  $-1, %r8d
    xorl  %r9d, %r9d
    syscall
    movq  %rax, 0x30(%r11)

.probe_done:
#else
    /* dlopen(agent, RTLD_NOW) */
    movq  0x00(%r11), %rdi
    movq  0x08(%r11), %r10
    movl  $2, %esi
    call  *%r10

    leaq  wieen_boot_data(%rip), %r11
    movb  $1, 0x28(%r11)
#endif

.done:
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rax

    xorl %eax, %eax
    ret
    .size wieen_boot, . - wieen_boot

    .align 8
wieen_boot_data:
    .quad 0 /* agent path */
    .quad 0 /* dlopen */
    .quad 0 /* patched function */
    .quad 0 /* original bytes, low  */
    .quad 0 /* original bytes, high */
    .byte 0 /* already loaded */
    .byte 0 /* trace marker */
    .quad 0 /* probe: socket */
    .quad 0 /* probe: openat */
    .quad 0 /* probe: mmap */
    .quad 0 /* probe selector */
    .align 8
wieen_boot_path:
    .asciz ""
