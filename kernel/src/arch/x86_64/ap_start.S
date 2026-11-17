/* Start-up code for the other CPUs (application processors). Copied to a
   page below 1 MiB (Smp::startOthers), where a STARTUP IPI starts a CPU in
   real mode at its first byte. It goes to protected mode, turns on paging
   with long mode, and jumps to apMain in the kernel with its own stack.
   The fields at the end are filled in by the kernel: the absolute
   addresses (the page's address isn't known when this is assembled), the
   page table (below 4 GiB: loaded from 32-bit code), and per CPU its
   stack, number and entry point. %ebx holds the page's address throughout. */

    .section .rodata
    .global apTrampolineStart, apTrampolineEnd
    .global apGdt, apGdtPointer, apProtected, apLong, apFarTo32, apFarTo64
    .global apPageTable, apStack, apCpu, apEntry
    .balign 16
apTrampolineStart:
    .code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    movzwl %ax, %ebx
    shll $4, %ebx                       /* the page's physical address */
    lgdtl (apGdtPointer - apTrampolineStart)
    movl %cr0, %eax
    orl $1, %eax                        /* protected mode */
    movl %eax, %cr0
    ljmpl *(apFarTo32 - apTrampolineStart)

    .code32
apProtected:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl %cr4, %eax
    orl $(1 << 5), %eax                 /* PAE */
    movl %eax, %cr4
    movl (apPageTable - apTrampolineStart)(%ebx), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx              /* EFER */
    rdmsr
    orl $((1 << 8) | (1 << 11)), %eax   /* long mode, no-execute */
    wrmsr
    movl %cr0, %eax
    orl $((1 << 31) | (1 << 16)), %eax  /* paging, write protect */
    movl %eax, %cr0
    ljmpl *(apFarTo64 - apTrampolineStart)(%ebx)

    .code64
apLong:
    movq (apStack - apTrampolineStart)(%rbx), %rsp
    movq (apCpu - apTrampolineStart)(%rbx), %rdi
    movq (apEntry - apTrampolineStart)(%rbx), %rax
    xorl %ebp, %ebp
    jmp *%rax

    .balign 8
apGdt:
    .quad 0
    .quad 0x00cf9a000000ffff            /* 0x08: 32-bit code */
    .quad 0x00cf92000000ffff            /* 0x10: data */
    .quad 0x00af9a000000ffff            /* 0x18: 64-bit code */
apGdtEnd:
apGdtPointer:
    .word apGdtEnd - apGdt - 1
    .long 0                             /* filled in: the GDT's address */
    .balign 4
apFarTo32:
    .long 0                             /* filled in: apProtected's address */
    .word 0x08
    .balign 4
apFarTo64:
    .long 0                             /* filled in: apLong's address */
    .word 0x18
    .balign 8
apPageTable:
    .quad 0
apStack:
    .quad 0
apCpu:
    .quad 0
apEntry:
    .quad 0
apTrampolineEnd:

    .section .note.GNU-stack, "", @progbits
