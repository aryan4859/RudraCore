/* Layout for Bhairav OS user programs. Each part starts on its own page so the
   kernel can give it its own permissions (code r-x, constants r--, data rw-). */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);   /* r-x */
    rodata PT_LOAD FLAGS(4); /* r-- */
    data PT_LOAD FLAGS(6);   /* rw- */
    tls PT_TLS FLAGS(4);     /* thread_local: the template (.tdata copied, .tbss zeroed per thread) */
}

SECTIONS
{
    . = 0x400000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);

    .data : {
        *(.data .data.*)
    } :data

    /* Thread-local storage. Kapala::Tls::create builds each thread's block
       from these (the linker's offsets assume variant II, block size rounded
       up to the alignment). */
    .tdata : {
        *(.tdata .tdata.*)
    } :data :tls
    .tbss : {
        *(.tbss .tbss.*)
        *(.tcommon)
    } :data :tls
    __tls_template = ADDR(.tdata);
    __tls_file_size = SIZEOF(.tdata);
    __tls_memory_size = ADDR(.tbss) + SIZEOF(.tbss) - ADDR(.tdata);
    __tls_align = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss));

    .init_array : {
        __init_array_start = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
        __init_array_end = .;
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
