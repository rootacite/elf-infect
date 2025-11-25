ENTRY(_emain)

PHDRS
{
    flat PT_LOAD FLAGS(7);
    dynamic PT_DYNAMIC;
}

SECTIONS
{
    . = 0;

    .text : {
        *(.init)
        *(.text*)
    } : flat

    .rodata : {
        *(.rodata*)
    } : flat

    .data : {
        *(.data*)
    } : flat

    .dynamic : {
        _dynamic_start = .;
        *(.dynamic)
        _dynamic_end = .;
    } : flat : dynamic

    .bss : {
        . = ALIGN(8);
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } : flat

    /DISCARD/ : {
        *(.interp)
        *(.comment)
        *(.eh_frame*)
    }

    .debug_aranges  0 : { *(.debug_aranges) }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
    .debug_abbrev   0 : { *(.debug_abbrev) }
    .debug_line     0 : { *(.debug_line .debug_line.* .debug_line_end) }
    .debug_frame    0 : { *(.debug_frame) }
    .debug_str      0 : { *(.debug_str) }
    .debug_loc      0 : { *(.debug_loc) }
    .debug_macinfo  0 : { *(.debug_macinfo) }
    
    /* DWARF 5 */
    .debug_macro    0 : { *(.debug_macro) }
    .debug_addr     0 : { *(.debug_addr) }

    .stab           0 : { *(.stab) }
    .stabstr        0 : { *(.stabstr) }
}