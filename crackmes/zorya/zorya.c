/* ============================================================================
 *  ZORYA  -  a hardened reverse-engineering crackme
 * ----------------------------------------------------------------------------
 *  Zorya, the Slavic auroral guardian, chains the doomsday hound Simargl to the
 *  pole star. Unchain her and the world ends; so the seal must hold against
 *  every prying tool. This binary is that seal.
 *
 *  Threat model / why the usual moves fail (author's note has the long form):
 *    * No keygen.      Licenses are Ed25519 *signed messages*. The verifier
 *                      holds only the public key; forging one == breaking
 *                      Ed25519. The signing (mint) path is compiled out unless
 *                      -DZORYA_MINT, and even then needs the secret-key file.
 *    * No magic patch. There is no boolean "if(ok) win" sink. *Correctness is
 *                      the decryption key.* The flag is XSalsa20 ciphertext;
 *                      its key is a SHA-512 fold of (a) the recomputed Ed25519
 *                      point t (== R iff the signature is real), (b) the signed
 *                      message, (c) the entered name, (d) a self-checksum of the
 *                      protected code section, (e) a single-step sensor bit, and
 *                      (f) a word that only a cooperating tracer can inject.
 *                      Disturb any input and you get a different key -> garbage.
 *    * Novel sensors.  (1) self-checksum over a named ELF section (a 0xCC
 *                      breakpoint there poisons the key); (2) single-step
 *                      detection via *context-switch* counters, not rdtsc;
 *                      (3) a self-ptrace fork that both blocks external attach
 *                      and hands the child a key-bearing word; (4) the key
 *                      schedule itself is encrypted VM bytecode delivered
 *                      page-by-page through userfaultfd.
 *
 *  Target: x86-64 Linux, gcc, -no-pie (stable .text for the self-checksum).
 *  Crypto: TweetNaCl (public domain) - SHA-512, Ed25519, XSalsa20.
 * ==========================================================================*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#include "tweetnacl.h"
#include "zcommon.h"

static inline long z_sc0(long n){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx","r11","memory");
    return r;
}
static inline long z_sc1(long n, long a){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx","r11","memory");
    return r;
}
static inline long z_sc2(long n, long a, long b){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b) : "rcx","r11","memory");
    return r;
}
static inline long z_sc3(long n, long a, long b, long c){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return r;
}
static inline long z_sc4(long n, long a, long b, long c, long d){
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}
static inline long z_sc5(long n, long a, long b, long c, long d, long e){
    long r; register long r10 __asm__("r10") = d; register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8) : "rcx","r11","memory");
    return r;
}
static inline long z_sc6(long n, long a, long b, long c, long d, long e, long f){
    long r; register long r10 __asm__("r10") = d; register long r8 __asm__("r8") = e; register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx","r11","memory");
    return r;
}

static inline int z_open_ro(const char *p){ return (int)z_sc4(SYS_openat, AT_FDCWD, (long)p, O_RDONLY, 0); }
static inline int z_open_rw(const char *p){ return (int)z_sc4(SYS_openat, AT_FDCWD, (long)p, O_RDWR, 0); }
static inline long z_read(int fd, void *p, size_t n){ return z_sc3(SYS_read, fd, (long)p, (long)n); }
static inline long z_write(int fd, const void *p, size_t n){ return z_sc3(SYS_write, fd, (long)p, (long)n); }
static inline long z_close(int fd){ return z_sc1(SYS_close, fd); }
static inline long z_pipe(int p[2]){ return z_sc1(SYS_pipe, (long)p); }
static inline long z_lseek(int fd, long off, int whence){ return z_sc3(SYS_lseek, fd, off, whence); }
static inline long z_pwrite(int fd, const void *p, size_t n, long off){ return z_sc4(SYS_pwrite64, fd, (long)p, (long)n, off); }
static inline void z_exit(int code){ z_sc1(SYS_exit_group, code); __builtin_unreachable(); }
static void z_puts_fd(int fd, const char *s){ z_write(fd, s, strlen(s)); }

/* randombytes is referenced by some TweetNaCl key routines. The verifier never
 * needs entropy (it only verifies); --gc-sections drops this there. The minter
 * uses it only for the (separate) keygen tool, not here. Defined once, safely. */
void randombytes(unsigned char *p, unsigned long long n){
    int fd = z_open_ro("/dev/urandom");
    if(fd >= 0){
        while(n){ long r = z_read(fd, p, n); if(r <= 0) break; p += (size_t)r; n -= (size_t)r; }
        z_close(fd);
    } else { while(n--) *p++ = 0; }
}

/* ===========================================================================
 *  VERIFIER
 * ==========================================================================*/
#ifndef ZORYA_MINT

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <pthread.h>
#include <poll.h>
#include <linux/userfaultfd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#include "zpub.h"      /* ZORYA_PK[32] */
#include "zbanner.h"   /* XOR-obfuscated banners */

/* ---- payload sections, patched by the sealer at issue time ----------------
 * Both must be PROGBITS (carry file bytes), never .bss; the leading non-zero
 * byte forces that, and we build with -fno-zero-initialized-in-bss as a belt. */
__attribute__((section("zoryabc"),  used, aligned(16)))
unsigned char ZBC[ZBC_LEN]     = { 0xA5 };   /* XSalsa20(bootstrap) ^ bytecode  */
__attribute__((section("zoryaseal"),used, aligned(16)))
unsigned char ZSEAL[ZSEAL_LEN] = { 0xA5 };   /* XSalsa20(key) ^ (MAGIC||flag)   */

/* the 16-byte plaintext prefix that proves an honest unseal (cosmetic check),
 * stored XOR-masked (0x5A) so `strings` reveals neither it nor the banner. */
static const unsigned char ZMAGIC_X[16] = {
    0x00,0x15,0x08,0x03,0x1b,0x2c,0x6b,0x60,0x0f,0x14,0x09,0x1f,0x1b,0x16,0x1f,0x1e };
static void z_unmask_magic(unsigned char m[16]){ for(int i=0;i<16;i++) m[i]=ZMAGIC_X[i]^0x5A; }

/* linker auto-symbols bounding the measured code section */
extern unsigned char __start_zoryatext[];
extern unsigned char __stop_zoryatext[];

#define ZT __attribute__((section("zoryatext"), noinline, used))

/* ---- self-checksum: SHA-512 over the protected section --------------------
 * Lives OUTSIDE zoryatext so it never measures itself. Under -no-pie the file
 * bytes equal the runtime bytes, so the sealer (reading the ELF) and the
 * verifier (reading memory) agree - unless someone planted a breakpoint or a
 * patch, which changes the digest and therefore the key. */
static void compute_checksum(unsigned char out[64]){
    size_t n = (size_t)(__stop_zoryatext - __start_zoryatext);
    crypto_hash(out, __start_zoryatext, n);
}

/* ---- single-step sensor: context-switch counters, not timing ---------------
 * A short, purely arithmetic loop should cost ~0 context switches. Single-step
 * (PTRACE_SINGLESTEP) traps every instruction, inflating switch counts by
 * orders of magnitude. We fold the branchless ge=(delta>=T) bit into the key,
 * so a stepping debugger silently corrupts the result instead of being told. */
static long z_perf_open(void){
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
    a.disabled = 1;
    a.exclude_kernel = 0;
    a.exclude_hv = 1;
    return z_sc5(SYS_perf_event_open, (long)&a, 0, -1, -1, 0);
}
static uint64_t z_busy_work(void){
    volatile uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for(int i = 0; i < 4096; i++){ acc = acc*6364136223846793005ULL + 1442695040888963407ULL; acc ^= acc>>29; }
    return acc;
}
static uint64_t z_singlestep_bit(void){
    const uint64_t T = 4;
    long fd = z_perf_open();
    if(fd >= 0){
        uint64_t c0 = 0, c1 = 0;
        z_sc3(SYS_ioctl, fd, PERF_EVENT_IOC_RESET, 0);
        z_sc3(SYS_ioctl, fd, PERF_EVENT_IOC_ENABLE, 0);
        if(z_read(fd, &c0, sizeof c0) != (long)sizeof c0) c0 = 0;
        volatile uint64_t sink = z_busy_work(); (void)sink;
        if(z_read(fd, &c1, sizeof c1) != (long)sizeof c1) c1 = c0;
        z_sc3(SYS_ioctl, fd, PERF_EVENT_IOC_DISABLE, 0);
        z_close((int)fd);
        uint64_t d = c1 - c0;
        return (uint64_t)(-(int64_t)(d >= T)) & 1ULL; /* branchless 0/1 */
    }
    /* fallback: thread rusage voluntary+involuntary switches */
    struct rusage r0, r1;
    if(z_sc2(SYS_getrusage, RUSAGE_THREAD, (long)&r0) == 0){
        volatile uint64_t sink = z_busy_work(); (void)sink;
        if(z_sc2(SYS_getrusage, RUSAGE_THREAD, (long)&r1) == 0){
            uint64_t d = (uint64_t)((r1.ru_nvcsw - r0.ru_nvcsw) + (r1.ru_nivcsw - r0.ru_nivcsw));
            return (uint64_t)(-(int64_t)(d >= T)) & 1ULL;
        }
    }
    return 0; /* sensor unavailable -> contribute 0 (honest default) */
}

/* ---- userfaultfd-delivered bytecode ---------------------------------------
 * The key schedule is a program for the stack-VM in zcommon.h. We never keep it
 * in cleartext: ZBC is ciphertext; we map an anonymous region, register it with
 * userfaultfd, and a handler thread decrypts and supplies each page only when
 * the VM first touches it. Tamper with the code section and the bootstrap key
 * (SHA-512(DOM_VM||checksum)) is wrong, so the "decrypted" bytecode is garbage,
 * the VM runs its defined-but-wrong diffusion path, and the key diverges. */
struct uffd_ctx {
    int          uffd;
    void        *region;
    unsigned char bootstrap[32];
    unsigned char plain[ZBC_LEN];
    int          decrypted;
};
static void uffd_decrypt_all(struct uffd_ctx *c){
    if(c->decrypted) return;
    crypto_stream_xor(c->plain, ZBC, ZBC_LEN, ZN_BC, c->bootstrap);
    c->decrypted = 1;
}
static void *uffd_thread(void *arg){
    struct uffd_ctx *c = (struct uffd_ctx*)arg;
    uffd_decrypt_all(c);                 /* page plaintext ready before serving */
    for(;;){
        struct pollfd pfd = { .fd = c->uffd, .events = POLLIN };
        int pr = (int)z_sc3(SYS_poll, (long)&pfd, 1, 1000);
        if(pr < 0){ if(pr == -EINTR) continue; break; }
        if(pr == 0) continue;
        struct uffd_msg msg;
        long got = z_read(c->uffd, &msg, sizeof msg);
        if(got <= 0){ if(got == -EAGAIN) continue; break; }
        if(msg.event != UFFD_EVENT_PAGEFAULT) continue;
        unsigned long addr = (unsigned long)msg.arg.pagefault.address & ~(unsigned long)(ZPAGE-1);
        unsigned long off  = addr - (unsigned long)c->region;
        if(off >= ZBC_LEN) continue;
        struct uffdio_copy cp;
        memset(&cp, 0, sizeof cp);
        cp.dst  = addr;
        cp.src  = (unsigned long)(c->plain + off);
        cp.len  = ZPAGE;
        cp.mode = 0;
        if(z_sc3(SYS_ioctl, c->uffd, UFFDIO_COPY, (long)&cp) < 0){
            /* if COPY races/fails, wake the faulting thread with zeros so we
             * never deadlock; the resulting key is simply wrong. */
            struct uffdio_zeropage zp; memset(&zp,0,sizeof zp);
            zp.range.start = addr; zp.range.len = ZPAGE;
            z_sc3(SYS_ioctl, c->uffd, UFFDIO_ZEROPAGE, (long)&zp);
        }
    }
    return NULL;
}
static volatile uint8_t z_rd_uffd(const void *ctx, size_t idx){
    return ((const volatile uint8_t*)ctx)[idx];
}
/* trampoline matching the z_reader prototype (drops volatile) */
static uint8_t z_rd_uffd_tr(const void *ctx, size_t idx){ return z_rd_uffd(ctx, idx); }

/* ---- the load-bearing key glue, kept inside the measured section ----------
 * Anything here is covered by the self-checksum, so a software breakpoint on
 * the key math is self-defeating. We deliberately funnel the VM run, the post
 * fold, and the seal decryption through this one routine. */
ZT static void zt_derive(const unsigned char t[32],
                         const unsigned char mclaimed[ZNAME_LEN],
                         const unsigned char name[ZNAME_LEN],
                         const unsigned char checksum[64],
                         uint64_t tracer_word, uint64_t ge,
                         const void *bc_ctx, z_reader rd,
                         unsigned char plain_out[ZSEAL_LEN]){
    uint8_t S[64];
    z_pre_state(t, mclaimed, name, S);
    z_vm_run(S, bc_ctx, rd, ZBC_LEN);
    unsigned char key[32];
    z_post_key(S, checksum, tracer_word, ge, key);
    crypto_stream_xor(plain_out, ZSEAL, ZSEAL_LEN, ZN_SEAL, key);
    /* scrub the transient key from the frame */
    volatile unsigned char *k = key; for(int i=0;i<32;i++) k[i]=0;
}

/* ---- the child: the actual verifier, traced by its parent -----------------*/
static int verifier_child(const char *name_in, const char *lic_in, int trace_wfd){
    /* (a) become traceable; stop so the parent can set options & arm itself */
    if(z_sc4(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) == 0){
        z_sc2(SYS_kill, z_sc0(SYS_getpid), SIGSTOP);
    } /* if TRACEME fails we're already traced (external debugger): the tracer
       * word will never arrive and the key will be wrong - by design. */

    /* (b) measure the protected section */
    unsigned char checksum[64];
    compute_checksum(checksum);

    /* (c) single-step sensor bit */
    uint64_t ge = z_singlestep_bit();

    /* (d) handshake stop: child sends the stack slot address to its real parent,
     * then stops while traced. The parent POKEs the tracer word into that slot. */
    uint64_t slot = 0;
    if(trace_wfd >= 0){
        uint64_t addr = (uint64_t)&slot;
        z_write(trace_wfd, &addr, sizeof addr);
        z_close(trace_wfd);
    }
    z_sc2(SYS_kill, z_sc0(SYS_getpid), SIGSTOP);
    uint64_t tracer_word = slot;   /* 0 unless our cooperating parent injected */

    /* (e) recompute the Ed25519 point from the license; decode sm = sig||msg */
    unsigned char sm[ZSM_LEN];
    memset(sm, 0, sizeof sm);
    long dl = z_b64_dec(lic_in ? lic_in : "", sm, sizeof sm);
    (void)dl;
    unsigned char t[32];
    if(z_ed25519_recompute(t, sm, (unsigned long long)ZSM_LEN, ZORYA_PK) != 0){
        memset(t, 0, sizeof t); /* invalid encoding -> wrong t -> wrong key */
    }
    const unsigned char *mclaimed = sm + 64;          /* the signed message    */
    unsigned char name[ZNAME_LEN];
    z_canon_name(name_in, name);

    /* (f) set up userfaultfd bytecode delivery (eager-decrypt fallback) */
    struct uffd_ctx *uc = NULL;
    pthread_t th; int th_live = 0;
    unsigned char plain[ZSEAL_LEN];

    long uffd = z_sc1(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if(uffd >= 0){
        struct uffdio_api api; memset(&api, 0, sizeof api); api.api = UFFD_API;
        if(z_sc3(SYS_ioctl, (int)uffd, UFFDIO_API, (long)&api) == 0){
            void *region = (void*)z_sc6(SYS_mmap, 0, ZBC_LEN, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if(region != MAP_FAILED){
                struct uffdio_register reg; memset(&reg, 0, sizeof reg);
                reg.range.start = (unsigned long)region;
                reg.range.len   = ZBC_LEN;
                reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
                if(z_sc3(SYS_ioctl, (int)uffd, UFFDIO_REGISTER, (long)&reg) == 0){
                    uc = (struct uffd_ctx*)calloc(1, sizeof *uc);
                    uc->uffd = (int)uffd;
                    uc->region = region;
                    z_bc_bootstrap(checksum, uc->bootstrap);
                    if(pthread_create(&th, NULL, uffd_thread, uc) == 0){
                        th_live = 1;
                        zt_derive(t, mclaimed, name, checksum, tracer_word, ge,
                                  region, z_rd_uffd_tr, plain);
                    } else { z_sc2(SYS_munmap, (long)region, ZBC_LEN); free(uc); uc = NULL; }
                } else { z_sc2(SYS_munmap, (long)region, ZBC_LEN); }
            }
        }
        if(!uc) z_close((int)uffd);
    }
    if(!uc){
        /* fallback: eager-decrypt the whole buffer; identical result */
        unsigned char bootstrap[32]; z_bc_bootstrap(checksum, bootstrap);
        static unsigned char flat[ZBC_LEN];
        crypto_stream_xor(flat, ZBC, ZBC_LEN, ZN_BC, bootstrap);
        zt_derive(t, mclaimed, name, checksum, tracer_word, ge,
                  flat, z_rd_flat, plain);
    }

    /* tear down the uffd machinery */
    if(uc){
        /* the handler loop exits when the fd is closed; nudge then close */
        if(th_live){ pthread_cancel(th); pthread_join(th, NULL); }
        z_sc2(SYS_munmap, (long)uc->region, ZBC_LEN);
        z_close(uc->uffd);
        free(uc);
    }

    /* (g) cosmetic magic check. Patching this to "always true" only prints the
     * garbage plaintext; it cannot conjure the real flag, because the flag
     * bytes are wrong whenever the key is wrong. */
    unsigned char magic[16]; z_unmask_magic(magic);
    int ok = (memcmp(plain, magic, 16) == 0);
    if(ok){
        zb_say(ZB_GRANTED, sizeof ZB_GRANTED);
        /* flag occupies plain[16..96), NUL-terminated/padded */
        for(unsigned i = 16; i < ZSEAL_LEN; i++){
            unsigned char ch = plain[i];
            if(ch == 0) break;
            z_write(1, &ch, 1);
        }
        zb_say(ZB_TAIL, sizeof ZB_TAIL);
    } else {
        zb_say(ZB_DENIED, sizeof ZB_DENIED);
    }
    return ok ? 0 : 1;
}

/* ---- the parent: cooperating tracer ---------------------------------------*/
static int verifier_parent(pid_t child, int trace_rfd){
    int status, exitcode = 1, injected = 0;
    long wr = z_sc4(SYS_wait4, child, (long)&status, 0, 0);
    if(wr < 0) return 1;     /* initial SIGSTOP */
    long pr0 = z_sc4(SYS_ptrace, PTRACE_SETOPTIONS, child, 0, (long)PTRACE_O_EXITKILL);
    (void)pr0;
    long pc0 = z_sc4(SYS_ptrace, PTRACE_CONT, child, 0, 0);
    (void)pc0;
    for(;;){
        pid_t w = (pid_t)z_sc4(SYS_wait4, child, (long)&status, 0, 0);
        if(w < 0){ if(w == -EINTR) continue; break; }
        if(WIFEXITED(status)){ exitcode = WEXITSTATUS(status); break; }
        if(WIFSIGNALED(status)){ exitcode = 128 + WTERMSIG(status); break; }
        if(!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if(sig == SIGTRAP){
            if(!injected){
                struct user_regs_struct regs;
                long gr = z_sc4(SYS_ptrace, PTRACE_GETREGS, child, 0, (long)&regs);
                if(gr == 0){
                    unsigned long slotaddr = regs.rdi;     /* child put &slot here */
                    long pk = z_sc4(SYS_ptrace, PTRACE_POKEDATA, child, (long)slotaddr,
                           (long)ZORYA_TRACER_WORD);
                    (void)pk;
                    injected = 1;
                }
            }
            long pc = z_sc4(SYS_ptrace, PTRACE_CONT, child, 0, 0);   /* swallow the trap   */
            (void)pc;
        } else if(sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU){
            if(sig == SIGSTOP && !injected){
                long slotaddr = 0;
                if(trace_rfd >= 0){
                    long rr = z_read(trace_rfd, &slotaddr, sizeof slotaddr);
                    (void)rr;
                    z_close(trace_rfd);
                    trace_rfd = -1;
                }
                if(slotaddr > 0){
                    long pk = z_sc4(SYS_ptrace, PTRACE_POKEDATA, child, slotaddr,
                                    (long)ZORYA_TRACER_WORD);
                    if(pk == 0) injected = 1;
                }
            }
            long pc = z_sc4(SYS_ptrace, PTRACE_CONT, child, 0, 0);   /* swallow group-stops */
            (void)pc;
        } else {
            long pc = z_sc4(SYS_ptrace, PTRACE_CONT, child, 0, sig); /* forward real signals */
            (void)pc;
        }
    }
    return exitcode;
}

static void usage(const char *a0){
    z_puts_fd(2, "ZORYA crackme\n  usage: ");
    z_puts_fd(2, a0);
    z_puts_fd(2, " <name> <license>\n         ");
    z_puts_fd(2, a0);
    z_puts_fd(2, "            (then answer the two prompts)\n");
}

static int z_readline(char *buf, size_t cap){
    size_t n = 0; int saw = 0;
    if(!cap) return 0;
    while(n + 1 < cap){
        char c;
        long r = z_read(0, &c, 1);
        if(r <= 0) break;
        saw = 1;
        if(c == '\r') continue;
        if(c == '\n') break;
        buf[n++] = c;
    }
    buf[n] = 0;
    return saw;
}

int main(int argc, char **argv){
    char namebuf[256], licbuf[8192];
    const char *name_in = NULL, *lic_in = NULL;
    int trace_pipe[2] = { -1, -1 };

    if(argc >= 3){
        name_in = argv[1];
        lic_in  = argv[2];
    } else if(argc == 1){
        z_puts_fd(1, "name> ");
        if(!z_readline(namebuf, sizeof namebuf)){ usage(argv[0]); return 2; }
        z_puts_fd(1, "license> ");
        if(!z_readline(licbuf, sizeof licbuf)){ usage(argv[0]); return 2; }
        name_in = namebuf; lic_in = licbuf;
    } else {
        usage(argv[0]); return 2;
    }

    z_pipe(trace_pipe);
    pid_t child = (pid_t)z_sc0(SYS_fork);
    if(child < 0){ z_puts_fd(2, "fork failed\n"); return 2; }
    if(child == 0){
        if(trace_pipe[0] >= 0) z_close(trace_pipe[0]);
        z_exit(verifier_child(name_in, lic_in, trace_pipe[1]));
    }
    if(trace_pipe[1] >= 0) z_close(trace_pipe[1]);
    return verifier_parent(child, trace_pipe[0]);
}

#else /* ====================================================================
 *  MINTER / SEALER  (only with -DZORYA_MINT; needs the secret-key file)
 * ==========================================================================*/

#include <elf.h>

static unsigned char SK[64];

static int load_sk(const char *path){
    int fd = z_open_ro(path); if(fd < 0) return -1;
    long r = z_read(fd, SK, sizeof SK); z_close(fd);
    return (r == (long)sizeof SK) ? 0 : -1;
}

/* base64url-encode a signed message into a license string */
static void mint_license(const char *name){
    unsigned char msg[ZNAME_LEN]; z_canon_name(name, msg);
    unsigned char sm[64 + ZNAME_LEN]; unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, msg, ZNAME_LEN, SK);
    char out[2*(64+ZNAME_LEN)+4];
    z_b64_enc(sm, (size_t)smlen, out);
    printf("%s\n", out);
}

/* minimal ELF64 helper: find a section by name -> file offset + size + addr */
struct sec { long off; unsigned long size; unsigned long addr; };
static int find_section(const unsigned char *elf, size_t n, const char *want, struct sec *s){
    if(n < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)elf;
    if(memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    const Elf64_Shdr *sh = (const Elf64_Shdr*)(elf + eh->e_shoff);
    const Elf64_Shdr *shstr = &sh[eh->e_shstrndx];
    const char *names = (const char*)(elf + shstr->sh_offset);
    for(unsigned i = 0; i < eh->e_shnum; i++){
        const char *nm = names + sh[i].sh_name;
        if(strcmp(nm, want) == 0){
            s->off  = (long)sh[i].sh_offset;
            s->size = (unsigned long)sh[i].sh_size;
            s->addr = (unsigned long)sh[i].sh_addr;
            return 0;
        }
    }
    return -1;
}

/* seal a freshly-built verifier ELF for one winner (name, flag) */
static int mint_seal(const char *elfpath, const char *name, const char *flagpath){
    /* slurp the target ELF */
    int fd = z_open_rw(elfpath); if(fd < 0){ fprintf(stderr, "open elf failed\n"); return 1; }
    long end = z_lseek(fd, 0, SEEK_END); z_lseek(fd, 0, SEEK_SET);
    unsigned char *elf = malloc((size_t)end);
    if(z_read(fd, elf, (size_t)end) != end){ fprintf(stderr, "read elf failed\n"); z_close(fd); return 1; }

    struct sec sx, sbc, ssl;
    if(find_section(elf, (size_t)end, "zoryatext", &sx) ||
       find_section(elf, (size_t)end, "zoryabc",   &sbc) ||
       find_section(elf, (size_t)end, "zoryaseal", &ssl)){
        fprintf(stderr, "seal: target is missing a zorya* section\n");
        free(elf); z_close(fd); return 1;
    }
    if(sbc.size != ZBC_LEN || ssl.size != ZSEAL_LEN){
        fprintf(stderr, "seal: section size mismatch (bc=%lu seal=%lu)\n", sbc.size, ssl.size);
        free(elf); z_close(fd); return 1;
    }

    /* checksum over the target's protected section, exactly as the verifier
     * will at runtime (-no-pie => file bytes == memory bytes) */
    unsigned char checksum[64];
    crypto_hash(checksum, elf + sx.off, (unsigned long long)sx.size);

    /* honest-run constants */
    const uint64_t tracer_word = ZORYA_TRACER_WORD;
    const uint64_t ge = 0;

    /* recompute t exactly as the verifier does, from our own signature */
    unsigned char msg[ZNAME_LEN]; z_canon_name(name, msg);
    unsigned char sm[64 + ZNAME_LEN]; unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, msg, ZNAME_LEN, SK);
    unsigned char t[32];
    if(z_ed25519_recompute(t, sm, smlen, /*pk=*/SK+32) != 0){
        fprintf(stderr, "seal: recompute failed\n"); free(elf); z_close(fd); return 1;
    }
    const unsigned char *mclaimed = sm + 64;

    /* generate + encrypt the VM bytecode -> patch zoryabc */
    static unsigned char bc_plain[ZBC_LEN];
    z_gen_bytecode(bc_plain);
    unsigned char bootstrap[32]; z_bc_bootstrap(checksum, bootstrap);
    static unsigned char bc_ct[ZBC_LEN];
    crypto_stream_xor(bc_ct, bc_plain, ZBC_LEN, ZN_BC, bootstrap);

    /* run the VM on plaintext to get S, then the post key */
    uint8_t S[64];
    z_pre_state(t, mclaimed, msg, S);
    z_vm_run(S, bc_plain, z_rd_flat, ZBC_LEN);
    unsigned char key[32];
    z_post_key(S, checksum, tracer_word, ge, key);

    /* build MAGIC||flag plaintext, encrypt -> patch zoryaseal */
    unsigned char plain[ZSEAL_LEN];
    memcpy(plain, "ZORYAv1:UNSEALED", 16);
    memset(plain + 16, 0, ZSEAL_LEN - 16);
    {
        int ffd = z_open_ro(flagpath);
        if(ffd < 0){ fprintf(stderr, "open flag failed\n"); free(elf); z_close(fd); return 1; }
        long fr = z_read(ffd, plain + 16, ZSEAL_LEN - 16 - 1);
        z_close(ffd);
        if(fr <= 0){ fprintf(stderr, "seal: empty flag\n"); free(elf); z_close(fd); return 1; }
        /* trim trailing newline */
        size_t fl = (size_t)fr;
        while(fl && (plain[16+fl-1]=='\n' || plain[16+fl-1]=='\r')) fl--;
        plain[16+fl] = 0;
    }
    unsigned char seal_ct[ZSEAL_LEN];
    crypto_stream_xor(seal_ct, plain, ZSEAL_LEN, ZN_SEAL, key);

    /* write both patched sections back into the ELF in place */
    if(z_pwrite(fd, bc_ct,   ZBC_LEN,   sbc.off) != (long)ZBC_LEN ||
       z_pwrite(fd, seal_ct, ZSEAL_LEN, ssl.off) != (long)ZSEAL_LEN){
        fprintf(stderr, "pwrite failed\n"); free(elf); z_close(fd); return 1;
    }
    z_close(fd); free(elf);

    /* emit the matching license so the author can hand it to the winner */
    char lic[2*(64+ZNAME_LEN)+4];
    z_b64_enc(sm, (size_t)smlen, lic);
    fprintf(stderr, "sealed %s for \"%s\"\n", elfpath, name);
    fprintf(stderr, "license: ");
    printf("%s\n", lic);

    /* scrub */
    volatile unsigned char *z = key; for(int i=0;i<32;i++) z[i]=0;
    return 0;
}

int main(int argc, char **argv){
    if(argc >= 3 && strcmp(argv[1], "license") == 0){
        if(load_sk("zorya.sk")){ fprintf(stderr, "cannot read zorya.sk\n"); return 1; }
        mint_license(argv[2]);
        return 0;
    }
    if(argc >= 5 && strcmp(argv[1], "seal") == 0){
        if(load_sk("zorya.sk")){ fprintf(stderr, "cannot read zorya.sk\n"); return 1; }
        return mint_seal(argv[2], argv[3], argv[4]);
    }
    fprintf(stderr,
        "ZORYA minter (privileged; do not ship)\n"
        "  %s license <name>\n"
        "  %s seal <verifier-elf> <name> <flagfile>\n", argv[0], argv[0]);
    return 2;
}

#endif /* ZORYA_MINT */
