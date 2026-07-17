/* SPDX-License-Identifier: MIT */

#include "morok_native_pack_config.h"

    .section .morok.npack.meta,"a",@progbits
    .balign 16
    .globl __morok_npack_meta
    .hidden __morok_npack_meta
    .type __morok_npack_meta,@object
__morok_npack_meta:
    .byte MOROK_NPACK_MARKER_BYTES
    .long 1                       /* format version */
    .long 1                       /* Linux ELF64, one lazy group */
    .quad __morok_npack_start - __morok_npack_meta
    /* The assembler cannot subtract two undefined linker-script symbols.
     * Before finalization this slot is end-relative-to-metadata; the finalizer
     * derives and writes the runtime byte length in place. */
    .quad __morok_npack_end - __morok_npack_meta
    .zero 12                      /* nonce: finalizer */
    .zero 4
    .zero 16                      /* Poly1305 tag: finalizer */
    .quad 0                       /* finalized cookie */
    .zero 32                      /* second key share: finalizer */
    .byte MOROK_NPACK_SALT_BYTES
    .size __morok_npack_meta, . - __morok_npack_meta

    .section .note.GNU-stack,"",@progbits
