/* Find an 8-byte tail nonce so that SHA-256(file) starts with a target prefix.
 * The file length is L with L % 64 == 8, so the nonce plus the SHA-256 padding
 * fit in one final block.  Everything before it is folded into a midstate once. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S0(x) (ROR(x,2)^ROR(x,13)^ROR(x,22))
#define S1(x) (ROR(x,6)^ROR(x,11)^ROR(x,25))
#define s0(x) (ROR(x,7)^ROR(x,18)^((x)>>3))
#define s1(x) (ROR(x,17)^ROR(x,19)^((x)>>10))

static void compress(uint32_t st[8], const uint32_t w_in[16]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2; int i;
    for (i = 0; i < 16; i++) w[i] = w_in[i];
    for (i = 16; i < 64; i++) w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    a=st[0];b=st[1];c=st[2];d=st[3];e=st[4];f=st[5];g=st[6];h=st[7];
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + ((e&f)^(~e&g)) + K[i] + w[i];
        t2 = S0(a) + ((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

static uint32_t midstate[8];
static uint32_t tailw[16];          /* final block template, nonce goes in w[0..1] */
static uint8_t  target[32];
static int      nbits;              /* how many leading bits must match */
static int      nthreads;
static volatile int found = 0;
static uint64_t found_nonce = 0;
static volatile uint64_t tried = 0;

static int prefix_ok(const uint32_t st[8]) {
    int full = nbits >> 3, rem = nbits & 7, i;
    uint8_t d[32];
    for (i = 0; i < 8; i++) {
        d[4*i+0] = st[i]>>24; d[4*i+1] = st[i]>>16; d[4*i+2] = st[i]>>8; d[4*i+3] = st[i];
    }
    for (i = 0; i < full; i++) if (d[i] != target[i]) return 0;
    if (rem) { uint8_t m = (uint8_t)(0xFF << (8-rem)); if ((d[full]&m) != (target[full]&m)) return 0; }
    return 1;
}

static void *worker(void *arg) {
    uint64_t id = (uint64_t)(intptr_t)arg, n = id, local = 0;
    uint32_t st[8], w[16];
    while (!found) {
        memcpy(w, tailw, sizeof(w));
        w[0] = (uint32_t)(n >> 32);
        w[1] = (uint32_t)n;
        memcpy(st, midstate, sizeof(st));
        compress(st, w);
        if (prefix_ok(st)) { found_nonce = n; found = 1; break; }
        n += nthreads;
        if ((++local & 0xFFFFFF) == 0) { __sync_fetch_and_add(&tried, 0x1000000); }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s file targethex nbits nthreads\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(L);
    if (fread(buf, 1, L, f) != (size_t)L) { perror("read"); return 1; }
    fclose(f);
    if (L % 64 != 8) { fprintf(stderr, "file length %ld is not 8 mod 64\n", L); return 1; }

    const char *hex = argv[2];
    nbits = atoi(argv[3]);
    nthreads = atoi(argv[4]);
    memset(target, 0, sizeof(target));
    for (int i = 0; i < (nbits + 7) / 8; i++) {
        char b[3] = { hex[2*i], hex[2*i+1] ? hex[2*i+1] : '0', 0 };
        target[i] = (uint8_t)strtol(b, NULL, 16);
    }

    /* fold every complete block before the nonce into the midstate */
    midstate[0]=0x6a09e667;midstate[1]=0xbb67ae85;midstate[2]=0x3c6ef372;midstate[3]=0xa54ff53a;
    midstate[4]=0x510e527f;midstate[5]=0x9b05688c;midstate[6]=0x1f83d9ab;midstate[7]=0x5be0cd19;
    for (long off = 0; off + 64 <= L - 8; off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = (buf[off+4*i]<<24)|(buf[off+4*i+1]<<16)|(buf[off+4*i+2]<<8)|buf[off+4*i+3];
        compress(midstate, w);
    }
    /* final block: 8 nonce bytes, 0x80, zero fill, 64-bit big-endian bit length */
    memset(tailw, 0, sizeof(tailw));
    tailw[2]  = 0x80000000u;
    tailw[14] = (uint32_t)(((uint64_t)L * 8) >> 32);
    tailw[15] = (uint32_t)((uint64_t)L * 8);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_t th[64];
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, (void*)(intptr_t)i);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "found after ~%.3g tries in %.1fs (%.1f Mtries/s)\n",
            (double)found_nonce, dt, (double)found_nonce / dt / 1e6);
    printf("%016llx\n", (unsigned long long)found_nonce);
    return 0;
}
