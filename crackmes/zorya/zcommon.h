/* zcommon.h - deterministic primitives shared by the verifier, the sealer and
 * the (ifdef'd) minter. Nothing environment-specific lives here: every routine
 * is a pure function of its inputs so that all three tools agree bit-for-bit on
 * the composite key. Crypto primitives come from TweetNaCl (public domain):
 *   crypto_hash       = SHA-512
 *   crypto_sign_open  = Ed25519 verify
 *   crypto_stream_xor = XSalsa20
 */
#ifndef ZCOMMON_H
#define ZCOMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "tweetnacl.h"

/* ---- domain separation tags (fixed, public, carry no secret) ------------- */
#define DOM_PRE  "ZORYA/pre/v1"     /* license+name binding                    */
#define DOM_VM   "ZORYA/vm/v1"      /* bytecode bootstrap key (checksum-bound)  */
#define DOM_POST "ZORYA/post/v1"    /* final fold of all entropy sources        */
#define DOM_K    "ZORYA/key/v1"     /* derive XSalsa key from VM state          */
#define DOM_SEED "ZORYA/seed/v1"    /* deterministic bytecode generator seed    */

/* The word the cooperating tracer injects into the traced child on an honest
 * run. The sealer assumes this exact value; under an external debugger / a
 * stripped fork the child never receives it and the key diverges. */
#define ZORYA_TRACER_WORD 0x5a4f5259417631ffULL  /* "ZORYAv1" tail-tagged      */

/* Layout sizes. The bytecode buffer deliberately spans >1 page so userfaultfd
 * delivery requires multiple faults. */
#define ZBC_PAGES 2
#define ZPAGE     4096u
#define ZBC_LEN   (ZBC_PAGES * ZPAGE)
#define ZSEAL_LEN 96u               /* magic(16) + flag ciphertext(<=80)        */
#define ZNAME_LEN 64u               /* canonical name block                     */
#define ZSM_LEN   (64u + ZNAME_LEN) /* Ed25519 signed message: sig(64)+msg(64)  */

/* fixed nonces (public; security comes from the keys, not nonce secrecy) */
static const unsigned char ZN_BC[24]   = "ZORYA.nonce.bytecode.01";
static const unsigned char ZN_SEAL[24] = "ZORYA.nonce.sealflag.01";

/* ---- tiny helpers -------------------------------------------------------- */
static inline uint8_t z_rotl8(uint8_t x, unsigned n){ n&=7u; return (uint8_t)((x<<n)|(x>>((8u-n)&7u))); }

static inline void z_put64le(unsigned char *p, uint64_t v){
    for(int i=0;i<8;i++){ p[i]=(unsigned char)(v & 0xff); v>>=8; }
}

/* ---- name canonicalization: lowercase, strip spaces/punct-ish, fixed 64B -- */
static void z_canon_name(const char *in, unsigned char out[ZNAME_LEN]){
    memset(out,0,ZNAME_LEN);
    size_t o=0;
    for(size_t i=0; in && in[i] && o<ZNAME_LEN-1; i++){
        unsigned c=(unsigned char)in[i];
        if(c=='\r'||c=='\n'||c=='\t'||c==' ') continue;
        if(c>='A'&&c<='Z') c+=32u;
        out[o++]=(unsigned char)c;
    }
    out[0]=out[0]; /* keep */
    out[ZNAME_LEN-1]=(unsigned char)o; /* length tag in last byte */
}

/* ---- base64url (no padding) --------------------------------------------- */
static const char Z_B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static int z_b64_val(int c){
    if(c>='A'&&c<='Z')return c-'A';
    if(c>='a'&&c<='z')return c-'a'+26;
    if(c>='0'&&c<='9')return c-'0'+52;
    if(c=='-')return 62; if(c=='_')return 63;
    return -1;
}
static size_t z_b64_enc(const unsigned char *in,size_t n,char *out){
    size_t o=0; size_t i=0;
    while(i+3<=n){
        uint32_t v=(in[i]<<16)|(in[i+1]<<8)|in[i+2];
        out[o++]=Z_B64[(v>>18)&63]; out[o++]=Z_B64[(v>>12)&63];
        out[o++]=Z_B64[(v>>6)&63];  out[o++]=Z_B64[v&63];
        i+=3;
    }
    if(n-i==1){ uint32_t v=in[i]<<16; out[o++]=Z_B64[(v>>18)&63]; out[o++]=Z_B64[(v>>12)&63]; }
    else if(n-i==2){ uint32_t v=(in[i]<<16)|(in[i+1]<<8); out[o++]=Z_B64[(v>>18)&63]; out[o++]=Z_B64[(v>>12)&63]; out[o++]=Z_B64[(v>>6)&63]; }
    out[o]=0; return o;
}
/* decode; ignores '-' grouping dashes? No: '-' is a valid b64url char. We strip
 * only whitespace. returns bytes decoded or -1 */
static long z_b64_dec(const char *in, unsigned char *out, size_t outcap){
    uint32_t acc=0; int bits=0; size_t o=0;
    for(size_t i=0; in[i]; i++){
        int c=(unsigned char)in[i];
        if(c=='\r'||c=='\n'||c=='\t'||c==' ') continue;
        int v=z_b64_val(c);
        if(v<0) return -1;
        acc=(acc<<6)|(uint32_t)v; bits+=6;
        if(bits>=8){ bits-=8; if(o>=outcap) return -1; out[o++]=(unsigned char)((acc>>bits)&0xff); }
    }
    return (long)o;
}

/* ---- the bytecode VM ----------------------------------------------------- */
/* opcodes (1 byte) + operand (1 byte). state S is 64 bytes. cursor 0..63. */
enum { ZOP_XORC=0x11, ZOP_ADDC=0x12, ZOP_ROTL=0x13, ZOP_MULO=0x14,
       ZOP_SETP=0x15, ZOP_INCP=0x16, ZOP_MIXN=0x17, ZOP_SBOX=0x18,
       ZOP_SWEEP=0x19, ZOP_HALT=0x1f };

/* nonlinear S-box derived from a fixed constant (bijective via odd multiply) */
static void z_make_sbox(uint8_t sb[256]){
    for(int i=0;i<256;i++){
        uint8_t x=(uint8_t)i;
        x^=(uint8_t)(x>>4); x=(uint8_t)(x*0x1du); x^=0x63u; x=z_rotl8(x,3);
        sb[i]=x;
    }
}

/* execute bytecode `bc` (len bytes) against 64-byte state S, in place.
 * read_byte() is provided by the caller so the verifier can route reads through
 * the userfaultfd-backed region while the sealer reads a plain buffer. */
typedef uint8_t (*z_reader)(const void *ctx, size_t idx);

static void z_vm_run(uint8_t S[64], const void *bc_ctx, z_reader rd, size_t len){
    uint8_t sb[256]; z_make_sbox(sb);
    size_t ip=0; unsigned ptr=0; unsigned guard=0;
    while(ip+1<len && guard<200000u){
        guard++;
        uint8_t op=rd(bc_ctx, ip);
        uint8_t arg=rd(bc_ctx, ip+1);
        ip+=2;
        switch(op){
            case ZOP_XORC: S[ptr]^=arg; break;
            case ZOP_ADDC: S[ptr]=(uint8_t)(S[ptr]+arg); break;
            case ZOP_ROTL: S[ptr]=z_rotl8(S[ptr],arg); break;
            case ZOP_MULO: S[ptr]=(uint8_t)(S[ptr]*(uint8_t)(arg|1u)); break;
            case ZOP_SETP: ptr=arg&63u; break;
            case ZOP_INCP: ptr=(ptr+arg)&63u; break;
            case ZOP_MIXN: S[ptr]^=S[(ptr+arg)&63u]; break;
            case ZOP_SBOX: S[ptr]=sb[S[ptr]]; break;
            case ZOP_SWEEP: { unsigned r=(arg&7u)+1u; for(unsigned k=0;k<r;k++){
                              uint8_t carry=S[63];
                              for(int q=0;q<64;q++){ S[q]=(uint8_t)(sb[(uint8_t)(S[q]^carry)]+ (uint8_t)q); carry=S[q]; } } } break;
            case ZOP_HALT: return;
            default: /* treat unknown as a benign diffusion so a bad decrypt
                        still "runs" (and produces a wrong-but-defined state) */
                     S[ptr]^=op; S[(ptr+1)&63u]=(uint8_t)(S[(ptr+1)&63u]+arg); break;
        }
    }
}

/* simple reader over a flat const buffer (sealer / minter / uffd-fallback) */
static uint8_t z_rd_flat(const void *ctx, size_t idx){ return ((const uint8_t*)ctx)[idx]; }

/* ---- deterministic bytecode generator (sealer/minter only need this) ----- */
/* SplitMix64 over a SHA-512(DOM_SEED) seed -> a long, well-formed program that
 * ends in HALT and stays in-bounds. The verifier never generates; it only
 * executes whatever the (decrypted) buffer holds. */
static uint64_t z_sm64(uint64_t *s){
    uint64_t z=(*s+=0x9e3779b97f4a7c15ull);
    z=(z^(z>>30))*0xbf58476d1ce4e5b9ull;
    z=(z^(z>>27))*0x94d049bb133111ebull;
    return z^(z>>31);
}
static size_t z_gen_bytecode(uint8_t out[ZBC_LEN]){
    unsigned char h[64];
    const char *d=DOM_SEED;
    crypto_hash(h,(const unsigned char*)d,strlen(d));
    uint64_t st=0; for(int i=0;i<8;i++) st=(st<<8)|h[i];
    /* leave room for trailing HALT; fill almost the whole 2-page buffer so the
     * program crosses the page boundary (forces a 2nd userfaultfd fault). */
    size_t cap=ZBC_LEN-4;
    size_t o=0;
    static const uint8_t ops[]={ZOP_XORC,ZOP_ADDC,ZOP_ROTL,ZOP_MULO,ZOP_SETP,
                                ZOP_INCP,ZOP_MIXN,ZOP_SBOX,ZOP_SWEEP};
    while(o+2<=cap){
        uint64_t r=z_sm64(&st);
        uint8_t op=ops[(r>>3)%(sizeof ops)];
        uint8_t arg=(uint8_t)(r>>11);
        out[o++]=op; out[o++]=arg;
    }
    out[o++]=ZOP_HALT; out[o++]=0;
    while(o<ZBC_LEN) out[o++]=0; /* pad */
    return o;
}

/* ---- the composite key schedule ----------------------------------------- */
/* recomputed Ed25519 verification point, defined in tweetnacl.c */
extern int z_ed25519_recompute(unsigned char tout[32], const unsigned char *sm,
                               unsigned long long n, const unsigned char *pk);

/* pre = SHA512(DOM_PRE || t(32) || mclaimed(64) || name(64)) -> VM state.
 * t is the recomputed curve point: equal to the signature's R iff the signature
 * is genuine, so the initial state is cryptographically bound to a real sig. */
static void z_pre_state(const unsigned char t[32], const unsigned char mclaimed[ZNAME_LEN],
                        const unsigned char name[ZNAME_LEN], uint8_t S[64]){
    unsigned char buf[ sizeof(DOM_PRE)-1 + 32 + ZNAME_LEN + ZNAME_LEN ];
    size_t o=0;
    memcpy(buf+o,DOM_PRE,sizeof(DOM_PRE)-1); o+=sizeof(DOM_PRE)-1;
    memcpy(buf+o,t,32); o+=32;
    memcpy(buf+o,mclaimed,ZNAME_LEN); o+=ZNAME_LEN;
    memcpy(buf+o,name,ZNAME_LEN); o+=ZNAME_LEN;
    unsigned char h[64]; crypto_hash(h,buf,o); memcpy(S,h,64);
}

/* bootstrap key for bytecode decryption = SHA512(DOM_VM || checksum)[:32]     */
static void z_bc_bootstrap(const unsigned char checksum[64], unsigned char key[32]){
    unsigned char buf[sizeof(DOM_VM)-1+64]; size_t o=0;
    memcpy(buf+o,DOM_VM,sizeof(DOM_VM)-1); o+=sizeof(DOM_VM)-1;
    memcpy(buf+o,checksum,64); o+=64;
    unsigned char h[64]; crypto_hash(h,buf,o); memcpy(key,h,32);
}

/* post = SHA512(DOM_POST || S(64) || checksum(64) || LE64(tracer) || LE64(ge))
 * Kflag = post[:32], nonce32 = post[32:56] (we use 24 for XSalsa)             */
static void z_post_key(const uint8_t S[64], const unsigned char checksum[64],
                       uint64_t tracer_word, uint64_t ge,
                       unsigned char keyout[32]){
    unsigned char buf[sizeof(DOM_POST)-1 + 64 + 64 + 8 + 8]; size_t o=0;
    memcpy(buf+o,DOM_POST,sizeof(DOM_POST)-1); o+=sizeof(DOM_POST)-1;
    memcpy(buf+o,S,64); o+=64;
    memcpy(buf+o,checksum,64); o+=64;
    z_put64le(buf+o,tracer_word); o+=8;
    z_put64le(buf+o,ge); o+=8;
    unsigned char h[64]; crypto_hash(h,buf,o); memcpy(keyout,h,32);
}

#endif /* ZCOMMON_H */
