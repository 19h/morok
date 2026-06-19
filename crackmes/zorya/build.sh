#!/bin/sh
# ZORYA build. Produces:
#   keygen        - one-shot keypair generator (writes zpub.h + zorya.sk)
#   zorya         - the shipped verifier (the crackme)
#   zorya-mint    - privileged minter/sealer (NEVER ship this or zorya.sk)
set -e

CC=${CC:-gcc}
# -no-pie               : fixed addresses so the .text self-checksum is stable
# -fno-zero-initialized-in-bss : keep ZBC/ZSEAL as PROGBITS (carry file bytes)
# -ffunction-sections -fdata-sections -Wl,--gc-sections : drop unused TweetNaCl
COMMON="-O2 -fno-pie -no-pie -fno-zero-initialized-in-bss \
        -ffunction-sections -fdata-sections -Wl,--gc-sections"

# (re)generate keypair only if missing
if [ ! -f zorya.sk ] || [ ! -f zpub.h ]; then
    $CC -O2 keygen.c tweetnacl.c -o keygen
    ./keygen
fi

echo "[*] building verifier (zorya)"
# -s strips the symbol table: a shipped crackme should give up no symbol names
# (zt_derive, uffd_thread, ZB_GRANTED, ...). The sealer needs only section
# headers + .shstrtab, which strip keeps, so sealing a stripped binary is fine.
$CC $COMMON -s zorya.c tweetnacl.c -o zorya -lpthread

echo "[*] building minter (zorya-mint)"
# minter is issuer-only and never shipped; leave it unstripped for convenience
$CC $COMMON -DZORYA_MINT zorya.c tweetnacl.c -o zorya-mint

echo "[*] done"
