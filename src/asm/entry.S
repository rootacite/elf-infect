.global _emain
.global _old_entry
.global _load_address_offset
.global _self_size
.global create_thread

.extern embedded

.section .rodata, "a", @progbits
_old_entry:
.8byte 0
_load_address_offset:
.8byte 0
_self_size:
.8byte 0

.section .data, "aw", @progbits
_solt:
.8byte 0
_old_fs:
.8byte 0
_tcb:
.space 512, 0
_pargc:
.8byte
_envp:
.8byte

.section .init, "ax", @progbits

_emain:
    movq    %rsp, _pargc(%rip)
    push    %rax
    push    %rbx
    push    %rcx
    push    %rdx
    push    %rdi
    push    %rsi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    push    %rbp
    movq    %rsp, %rbp

    movq    $158, %rax
    movq    $0x1003, %rdi
    leaq    _old_fs(%rip), %rsi
    syscall

    # calc envp
    movq    _pargc(%rip), %rdi
    movq    (%rdi), %rdi
    incq    %rdi
    imulq   $8, %rdi, %rdi
    movq    _pargc(%rip), %rsi
    addq    $8, %rsi
    addq    %rdi, %rsi
    movq    %rsi, _envp(%rip)

    movq    $158, %rax
    leaq    _tcb(%rip), %rsi
    movq    %rsi, (%rsi)
    movq    $0xDEADBEEF, %rcx
    movq    %rcx, 0x28(%rsi)
    movq    $0x1002, %rdi
    syscall

.Lenter_main:
    sub     $16, %rsp
    andq    $0xfffffffffffffff0, %rsp
    leaq    _emain(%rip), %rdi
    leaq    _dynamic_start(%rip), %rsi
    movq    _self_size(%rip), %rdx
    addq    %rdi, %rdx  # Phdr address = Self size + Self load bias
    movq    _envp(%rip), %rcx
    call    embedded

    movq    $158, %rax
    movq    $0x1002, %rdi
    movq    _old_fs(%rip), %rsi
    syscall

    movq    _load_address_offset(%rip), %rcx
    leaq    _emain(%rip), %rdi
    subq    %rcx, %rdi
    movq    _old_entry(%rip), %rcx
    addq    %rcx, %rdi
    movq    %rdi, _solt(%rip)

    movq    _self_size(%rip), %rdi
    test    %rdi, %rdi

    jnz .Lexit_to_entey
    movq    $231, %rax
    movq    $0, %rdi
    syscall 

.Lexit_to_entey:
    movq    %rbp, %rsp
    pop     %rbp
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rsi
    pop     %rdi
    pop     %rdx
    pop     %rcx
    pop     %rbx
    pop     %rax
    jmp     *_solt(%rip)

create_thread:  # int create_thread(uint64_t flags, void* stacktop, void(*entry)())
    # rdi = flags
    # rsi = stacktop
    # rdx = entry
    push    %rbp
    movq    %rsp, %rbp

    push    %rbx
    movq    %rdx, %rbx
    movq    $56, %rax
    movq    $0, %rdx   # uint64 parent_tid
    movq    $0, %r10   # uint64 child_tid
    movq    $0, %r8    # uint64 tls
    syscall            # clone

    test    %eax, %eax
    jnz     .Lparent

    # rsp is in new thread
    subq    $512, %rsp

    movq    $158, %rax
    movq    %rsp, %rsi
    movq    %rsi, (%rsi)
    movq    $0xDEADBEEF, %rcx
    movq    %rcx, 0x28(%rsi)
    movq    $0x1002, %rdi
    syscall

    sub     $16, %rsp
    andq    $0xfffffffffffffff0, %rsp
    call    *%rbx
    
    movq    $60, %rax
    movq    $0, %rdi
    syscall 
.Lparent:
    pop     %rbx
    leave
    ret