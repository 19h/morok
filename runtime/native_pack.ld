/* SPDX-License-Identifier: MIT
 *
 * Supplement to LLD's default Linux ELF script.  A 64 KiB isolation quantum
 * covers the ordinary 4 KiB x86-64 page configuration and Linux AArch64
 * kernels built with 4/16/64 KiB base pages.  The protected region is padded
 * in the file so runtime decryption never changes a page containing its loader.
 */
SECTIONS
{
  .morok_npack_rx ALIGN(65536) : ALIGN(65536)
  {
    PROVIDE_HIDDEN(__morok_npack_start = .);
    KEEP(*(.morok.npack.text))
    KEEP(*(.morok.npack.text.*))
    . = ALIGN(65536);
    PROVIDE_HIDDEN(__morok_npack_end = .);
  }

  .morok_npack_ro : ALIGN(16)
  {
    KEEP(*(.morok.npack.meta))
  }
}
INSERT AFTER .text;
