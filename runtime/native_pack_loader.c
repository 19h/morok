// SPDX-License-Identifier: MIT
//
// Freestanding Linux ELF64 lazy native-code loader.  This translation unit is
// compiled separately from the protected program and must never be passed
// through Morok or ordinary instrumentation.

#include "morok_native_pack_config.h"

#include <stddef.h>
#include <stdint.h>

#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
#error "Morok native packing supports Linux ELF64 x86-64/AArch64 only"
#endif

struct __attribute__((packed, aligned(16))) morok_npack_meta {
    uint8_t marker[16];
    uint32_t version;
    uint32_t flags;
    int64_t begin_delta;
    uint64_t length;
    uint8_t nonce[12];
    uint8_t reserved[4];
    uint8_t tag[16];
    uint64_t cookie;
    uint8_t key_share[32];
    uint8_t salt[16];
};

extern const struct morok_npack_meta __morok_npack_meta
    __attribute__((visibility("hidden")));

static const uint8_t morok_npack_key_a[32] = {MOROK_NPACK_KEY_A_BYTES};
static uint32_t morok_npack_state;

static uint32_t np_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t np_load64(const uint8_t *p) {
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i != 8; ++i)
        v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static void np_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void np_store64(uint8_t *p, uint64_t v) {
    unsigned i;
    for (i = 0; i != 8; ++i)
        p[i] = (uint8_t)(v >> (i * 8));
}

static uint32_t np_rotl(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32u - n));
}

static void np_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = np_rotl(*d, 16);
    *c += *d; *b ^= *c; *b = np_rotl(*b, 12);
    *a += *b; *d ^= *a; *d = np_rotl(*d, 8);
    *c += *d; *b ^= *c; *b = np_rotl(*b, 7);
}

static void np_chacha_block(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, uint8_t out[64]) {
    uint32_t s[16] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    uint32_t x[16];
    unsigned i;
    for (i = 0; i != 8; ++i)
        s[4 + i] = np_load32(key + i * 4);
    s[12] = counter;
    s[13] = np_load32(nonce);
    s[14] = np_load32(nonce + 4);
    s[15] = np_load32(nonce + 8);
    for (i = 0; i != 16; ++i)
        x[i] = s[i];
    for (i = 0; i != 10; ++i) {
        np_qr(&x[0], &x[4], &x[8], &x[12]);
        np_qr(&x[1], &x[5], &x[9], &x[13]);
        np_qr(&x[2], &x[6], &x[10], &x[14]);
        np_qr(&x[3], &x[7], &x[11], &x[15]);
        np_qr(&x[0], &x[5], &x[10], &x[15]);
        np_qr(&x[1], &x[6], &x[11], &x[12]);
        np_qr(&x[2], &x[7], &x[8], &x[13]);
        np_qr(&x[3], &x[4], &x[9], &x[14]);
    }
    for (i = 0; i != 16; ++i)
        np_store32(out + i * 4, x[i] + s[i]);
}

struct np_poly {
    uint64_t r[5];
    uint64_t h[5];
    uint32_t pad[4];
    uint8_t buffer[16];
    size_t leftover;
};

static void np_poly_init(struct np_poly *p, const uint8_t key[32]) {
    uint32_t t0 = np_load32(key), t1 = np_load32(key + 4);
    uint32_t t2 = np_load32(key + 8), t3 = np_load32(key + 12);
    unsigned i;
    p->r[0] = t0 & 0x3ffffffu;
    p->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    p->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    p->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    p->r[4] = (t3 >> 8) & 0x00fffffu;
    for (i = 0; i != 5; ++i)
        p->h[i] = 0;
    for (i = 0; i != 4; ++i)
        p->pad[i] = np_load32(key + 16 + i * 4);
    p->leftover = 0;
}

static void np_poly_blocks(struct np_poly *p, const uint8_t *in, size_t bytes,
                           uint64_t hibit) {
    const uint64_t s1 = p->r[1] * 5, s2 = p->r[2] * 5;
    const uint64_t s3 = p->r[3] * 5, s4 = p->r[4] * 5;
    while (bytes >= 16) {
        uint32_t t0 = np_load32(in), t1 = np_load32(in + 4);
        uint32_t t2 = np_load32(in + 8), t3 = np_load32(in + 12);
        uint64_t d0, d1, d2, d3, d4, c, v;
        p->h[0] += t0 & 0x3ffffffu;
        p->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffffu;
        p->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
        p->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
        p->h[4] += (t3 >> 8) | hibit;
        d0 = p->h[0]*p->r[0] + p->h[1]*s4 + p->h[2]*s3 + p->h[3]*s2 + p->h[4]*s1;
        d1 = p->h[0]*p->r[1] + p->h[1]*p->r[0] + p->h[2]*s4 + p->h[3]*s3 + p->h[4]*s2;
        d2 = p->h[0]*p->r[2] + p->h[1]*p->r[1] + p->h[2]*p->r[0] + p->h[3]*s4 + p->h[4]*s3;
        d3 = p->h[0]*p->r[3] + p->h[1]*p->r[2] + p->h[2]*p->r[1] + p->h[3]*p->r[0] + p->h[4]*s4;
        d4 = p->h[0]*p->r[4] + p->h[1]*p->r[3] + p->h[2]*p->r[2] + p->h[3]*p->r[1] + p->h[4]*p->r[0];
        c = d0 >> 26; p->h[0] = d0 & 0x3ffffffu;
        v = d1 + c; c = v >> 26; p->h[1] = v & 0x3ffffffu;
        v = d2 + c; c = v >> 26; p->h[2] = v & 0x3ffffffu;
        v = d3 + c; c = v >> 26; p->h[3] = v & 0x3ffffffu;
        v = d4 + c; c = v >> 26; p->h[4] = v & 0x3ffffffu;
        p->h[0] += c * 5; c = p->h[0] >> 26;
        p->h[0] &= 0x3ffffffu; p->h[1] += c;
        in += 16; bytes -= 16;
    }
}

static void np_poly_update(struct np_poly *p, const uint8_t *in, size_t bytes) {
    size_t i, want, full;
    if (p->leftover) {
        want = 16 - p->leftover;
        if (want > bytes) want = bytes;
        for (i = 0; i != want; ++i)
            p->buffer[p->leftover + i] = in[i];
        p->leftover += want; in += want; bytes -= want;
        if (p->leftover < 16) return;
        np_poly_blocks(p, p->buffer, 16, 1u << 24);
        p->leftover = 0;
    }
    full = bytes & ~(size_t)15;
    if (full) {
        np_poly_blocks(p, in, full, 1u << 24);
        in += full; bytes -= full;
    }
    for (i = 0; i != bytes; ++i)
        p->buffer[i] = in[i];
    p->leftover = bytes;
}

static void np_poly_finish(struct np_poly *p, uint8_t tag[16]) {
    uint64_t c, mask, notmask, f0, f1, f2, f3, g[5];
    unsigned i;
    if (p->leftover) {
        p->buffer[p->leftover] = 1;
        for (i = (unsigned)p->leftover + 1; i != 16; ++i)
            p->buffer[i] = 0;
        np_poly_blocks(p, p->buffer, 16, 0);
    }
    c = p->h[1] >> 26; p->h[1] &= 0x3ffffffu; p->h[2] += c;
    c = p->h[2] >> 26; p->h[2] &= 0x3ffffffu; p->h[3] += c;
    c = p->h[3] >> 26; p->h[3] &= 0x3ffffffu; p->h[4] += c;
    c = p->h[4] >> 26; p->h[4] &= 0x3ffffffu; p->h[0] += c * 5;
    c = p->h[0] >> 26; p->h[0] &= 0x3ffffffu; p->h[1] += c;
    g[0] = p->h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffffu;
    for (i = 1; i != 4; ++i) {
        g[i] = p->h[i] + c; c = g[i] >> 26; g[i] &= 0x3ffffffu;
    }
    g[4] = p->h[4] + c - ((uint64_t)1 << 26);
    mask = (g[4] >> 63) - 1; notmask = ~mask;
    for (i = 0; i != 5; ++i)
        p->h[i] = (p->h[i] & notmask) | (g[i] & mask);
    f0 = (p->h[0] | (p->h[1] << 26)) & 0xffffffffu;
    f1 = ((p->h[1] >> 6) | (p->h[2] << 20)) & 0xffffffffu;
    f2 = ((p->h[2] >> 12) | (p->h[3] << 14)) & 0xffffffffu;
    f3 = ((p->h[3] >> 18) | (p->h[4] << 8)) & 0xffffffffu;
    f0 += p->pad[0]; f1 += p->pad[1] + (f0 >> 32); f0 &= 0xffffffffu;
    f2 += p->pad[2] + (f1 >> 32); f1 &= 0xffffffffu;
    f3 += p->pad[3] + (f2 >> 32);
    np_store32(tag, (uint32_t)f0); np_store32(tag + 4, (uint32_t)f1);
    np_store32(tag + 8, (uint32_t)f2); np_store32(tag + 12, (uint32_t)f3);
}

static void np_make_aad(const struct morok_npack_meta *m, uint8_t aad[40]) {
    const uint8_t *head = (const uint8_t *)&m->version;
    unsigned i;
    for (i = 0; i != 24; ++i) aad[i] = head[i];
    for (i = 0; i != 16; ++i) aad[24 + i] = m->salt[i];
}

static void np_tag(const uint8_t *cipher, size_t bytes, const uint8_t aad[40],
                   const uint8_t key[32], const uint8_t nonce[12],
                   uint8_t tag[16]) {
    uint8_t block[64], polykey[32], zero[16] = {0}, lengths[16];
    struct np_poly p;
    unsigned i;
    np_chacha_block(key, nonce, 0, block);
    for (i = 0; i != 32; ++i) polykey[i] = block[i];
    np_poly_init(&p, polykey);
    np_poly_update(&p, aad, 40);
    np_poly_update(&p, zero, 8);
    np_poly_update(&p, cipher, bytes);
    if (bytes & 15u) np_poly_update(&p, zero, 16 - (bytes & 15u));
    np_store64(lengths, 40); np_store64(lengths + 8, bytes);
    np_poly_update(&p, lengths, 16);
    np_poly_finish(&p, tag);
    for (i = 0; i != 64; ++i) block[i] = 0;
    for (i = 0; i != 32; ++i) polykey[i] = 0;
}

static int np_tag_equal(const uint8_t a[16], const uint8_t b[16]) {
    uint32_t diff = 0;
    unsigned i;
    for (i = 0; i != 16; ++i) diff |= (uint32_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void np_xor(uint8_t *p, size_t bytes, const uint8_t key[32],
                   const uint8_t nonce[12]) {
    uint8_t block[64];
    uint32_t counter = 1;
    size_t off = 0, n, i;
    while (off < bytes) {
        np_chacha_block(key, nonce, counter++, block);
        n = bytes - off; if (n > 64) n = 64;
        for (i = 0; i != n; ++i) p[off + i] ^= block[i];
        off += n;
    }
    for (i = 0; i != 64; ++i) block[i] = 0;
}

static long np_mprotect(void *addr, size_t length, long prot) {
#if defined(__x86_64__)
    register long rax __asm__("rax") = 10;
    register long rdi __asm__("rdi") = (long)addr;
    register long rsi __asm__("rsi") = (long)length;
    register long rdx __asm__("rdx") = prot;
    __asm__ volatile("syscall" : "+a"(rax) : "D"(rdi), "S"(rsi), "d"(rdx)
                     : "rcx", "r11", "memory");
    return rax;
#else
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = (long)length;
    register long x2 __asm__("x2") = prot;
    register long x8 __asm__("x8") = 226;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
#endif
}

static long np_futex(uint32_t *word, long operation, uint32_t value) {
#if defined(__x86_64__)
    register long rax __asm__("rax") = 202;
    register long rdi __asm__("rdi") = (long)word;
    register long rsi __asm__("rsi") = operation;
    register long rdx __asm__("rdx") = value;
    register long r10 __asm__("r10") = 0;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ volatile("syscall" : "+a"(rax)
                     : "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10), "r"(r8),
                       "r"(r9)
                     : "rcx", "r11", "memory");
    return rax;
#else
    register long x0 __asm__("x0") = (long)word;
    register long x1 __asm__("x1") = operation;
    register long x2 __asm__("x2") = value;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x5 __asm__("x5") = 0;
    register long x8 __asm__("x8") = 98;
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "memory");
    return x0;
#endif
}

static void np_publish(uint32_t state) {
    __atomic_store_n(&morok_npack_state, state, __ATOMIC_RELEASE);
    /* FUTEX_WAKE_PRIVATE.  INT32_MAX wakes every first-entry waiter. */
    (void)np_futex(&morok_npack_state, 129, UINT32_C(0x7fffffff));
}

static void np_clear_cache(uint8_t *begin, uint8_t *end) {
#if defined(__aarch64__)
    uint64_t ctr;
    uintptr_t p, dline, iline;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    dline = (uintptr_t)4 << ((ctr >> 16) & 15);
    iline = (uintptr_t)4 << (ctr & 15);
    p = (uintptr_t)begin & ~(dline - 1);
    for (; p < (uintptr_t)end; p += dline)
        __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    p = (uintptr_t)begin & ~(iline - 1);
    for (; p < (uintptr_t)end; p += iline)
        __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
#else
    (void)begin; (void)end;
    __asm__ volatile("" ::: "memory");
#endif
}

__attribute__((visibility("hidden"), noinline, used))
int __morok_npack_open(void) {
    const struct morok_npack_meta *m = &__morok_npack_meta;
    uint32_t state = __atomic_load_n(&morok_npack_state, __ATOMIC_ACQUIRE);
    uint32_t expected;
    uint8_t key[32], aad[40], actual[16];
    uint8_t *begin;
    uint64_t expected_cookie, magnitude;
    uintptr_t meta_address;
    size_t i;

    if (state == 2) return 0;
    if (state == 3) return -1;
    expected = 0;
    if (!__atomic_compare_exchange_n(&morok_npack_state, &expected, 1, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        for (;;) {
            state = __atomic_load_n(&morok_npack_state, __ATOMIC_ACQUIRE);
            if (state == 2) return 0;
            if (state == 3) return -1;
            /* FUTEX_WAIT_PRIVATE sleeps only while the word remains 1.  A
             * signal or a value race merely causes the loop to recheck. */
            (void)np_futex(&morok_npack_state, 128, 1);
        }
    }

    expected_cookie = np_load64(m->tag) ^ m->length ^ np_load64(m->salt) ^
                      UINT64_C(0x9f4a7c15d3e26b81);
    if (m->version != 1) goto fail;
    if (m->flags != 1) goto fail;
    if (m->length == 0 || m->length > UINT64_C(0x40000000)) goto fail;
    if (m->begin_delta >= 0) goto fail;
    magnitude = (uint64_t)(-(m->begin_delta + 1)) + 1;
    meta_address = (uintptr_t)m;
    if (magnitude != m->length || magnitude > meta_address) goto fail;
    begin = (uint8_t *)(meta_address - (uintptr_t)magnitude);
    // The ELF section is 64 KiB-relative-aligned and its PT_LOAD advertises
    // that alignment.  A native loader on a 64 KiB-page kernel therefore
    // supplies a 64 KiB-aligned load bias.  User-mode emulators may honor only
    // the host's 4 KiB page quantum, so the absolute runtime check uses the
    // Linux minimum and lets mprotect enforce any larger native requirement.
    if (((uintptr_t)begin & UINT64_C(0xfff)) != 0) {
        goto fail;
    }
    if ((m->length & UINT64_C(0xffff)) != 0) {
        goto fail;
    }
    if (m->cookie != expected_cookie) goto fail;

    for (i = 0; i != 32; ++i) key[i] = morok_npack_key_a[i] ^ m->key_share[i];
    np_make_aad(m, aad);
    np_tag(begin, (size_t)m->length, aad, key, m->nonce, actual);
    if (!np_tag_equal(actual, m->tag)) goto fail_key;
    if (np_mprotect(begin, (size_t)m->length, 1 | 2) != 0) goto fail_key;
    np_xor(begin, (size_t)m->length, key, m->nonce);
    np_clear_cache(begin, begin + m->length);
    if (np_mprotect(begin, (size_t)m->length, 1 | 4) != 0) goto fail_key;
    for (i = 0; i != 32; ++i) key[i] = 0;
    np_publish(2);
    return 0;

fail_key:
    for (i = 0; i != 32; ++i) key[i] = 0;
fail:
    np_publish(3);
    return -1;
}
