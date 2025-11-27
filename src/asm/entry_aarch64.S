
.global _emain
.global _old_entry
.global _load_address_offset

.extern embedded
.extern _dynamic_start

.section .data, "wa", @progbits

_old_entry:
    .dword  0

_load_address_offset:
    .dword  0

.section .init, "ax", @progbits

_emain:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    sub     sp, sp, #512

    mov     x1, #0x76761313
    movk    x1, #0xaabbccdd, lsl #32
    cmp     x0, x1
    b.eq    enter_main

    mov     x2, sp
    str     x2, [x2]
    mov     x1, #0xdeadbeef
    str     x1, [x2, #0x28]
    mov     x8, #158
    mov     x0, #0x1002
    svc     #0

enter_main:
    sub     sp, sp, #16
    and     sp, sp, #-16

    adr     x0, _emain
    adr     x1, _dynamic_start
    ldr     x2, _old_entry
    ldr     x3, _load_address_offset

    bl      embedded

    mov     sp, x29
    ldp     x29, x30, [sp], #16
    ldr     x16, _old_entry
    br      x16