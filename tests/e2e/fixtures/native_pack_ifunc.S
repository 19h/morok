    .text
    .globl native_pack_ifunc
    .type native_pack_ifunc,@gnu_indirect_function
native_pack_ifunc:
    /* The finalizer must reject the symbol before this resolver can matter. */
    .byte 0
    .size native_pack_ifunc, . - native_pack_ifunc

    .section .note.GNU-stack,"",@progbits
