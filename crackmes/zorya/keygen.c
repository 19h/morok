/* issuer-only: emit zpub.h (public key, baked into verifier) + zorya.sk (secret) */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "tweetnacl.h"

static inline long k_sc1(long n, long a){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx","r11","memory");
    return r;
}
static inline long k_sc3(long n, long a, long b, long c){
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return r;
}
static inline long k_sc4(long n, long a, long b, long c, long d){
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}
static inline long k_write(int fd, const void *p, unsigned long long n){ return k_sc3(SYS_write,fd,(long)p,n); }
static void k_puts(int fd, const char *s){ const char *p=s; while(*p) p++; k_write(fd,s,(unsigned long long)(p-s)); }
static void k_putu(int fd, unsigned v){
    char b[10]; unsigned n=0;
    do { b[n++]=(char)('0'+(v%10)); v/=10; } while(v);
    while(n){ char c=b[--n]; k_write(fd,&c,1); }
}

void randombytes(unsigned char *p, unsigned long long n){
    int fd=(int)k_sc4(SYS_openat, AT_FDCWD, (long)"/dev/urandom", O_RDONLY, 0); long r;
    while(n){ r=k_sc3(SYS_read,fd,(long)p,n); if(r<=0) k_sc1(SYS_exit_group,9); p+=r; n-=r; } k_sc1(SYS_close,fd);
}
int main(void){
    unsigned char pk[32], sk[64];
    z_ed25519_keypair(pk,sk);
    int h=(int)k_sc4(SYS_openat, AT_FDCWD, (long)"zpub.h", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if(h<0) k_sc1(SYS_exit_group,8);
    k_puts(h,"/* generated - Ed25519 public key (verifier holds only this) */\n");
    k_puts(h,"static const unsigned char ZORYA_PK[32]={");
    for(int i=0;i<32;i++){ k_putu(h,pk[i]); k_puts(h, i<31?",":""); }
    k_puts(h,"};\n"); k_sc1(SYS_close,h);
    int s=(int)k_sc4(SYS_openat, AT_FDCWD, (long)"zorya.sk", O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if(s<0) k_sc1(SYS_exit_group,7);
    if(k_write(s,sk,64)!=64) k_sc1(SYS_exit_group,6);
    k_sc1(SYS_close,s);
    k_puts(2,"wrote zpub.h and zorya.sk\n");
    return 0;
}
