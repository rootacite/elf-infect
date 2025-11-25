.global _emain
.extern embedded

.section .init, "ax", @progbits

_emain:
    push    %rbp
    movq    %rsp, %rbp
    sub     $512, %rsp

    movq    $0xaabbccdd76761313, %rcx
    cmpq    %rdi, %rcx
    je enter_main

    movq    %rsp, %rsi
    movq    %rsi, (%rsi)
    movq    $0xDEADBEEF, %rcx
    movq    %rcx, 0x28(%rsi)
    movq    $158, %rax
    movq    $0x1002, %rdi
    syscall

enter_main:
    sub     $16, %rsp
    andq    $0xfffffffffffffff0, %rsp
    leaq    _emain(%rip), %rdi
    leaq    _dynamic_start(%rip), %rsi
    call    embedded

    movq    %rax,   %rdi
    movq    $60, %rax
    syscall
    int3
    
    movq    %rbp, %rsp
    pop    %rbp
    ret
