/* 16-lane AVX-512 version of the nonce search. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <immintrin.h>
#include <math.h>

static struct timespec start;

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

/* scalar SHA-256 compression, used for the midstate and for confirming a hit */
static void compress(uint32_t st[8], const uint32_t w_in[16]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2; int i;
    for (i = 0; i < 16; i++) w[i] = w_in[i];
    for (i = 16; i < 64; i++)
        w[i] = (ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10)) + w[i-7]
             + (ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3)) + w[i-16];
    a=st[0];b=st[1];c=st[2];d=st[3];e=st[4];f=st[5];g=st[6];h=st[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR(e,6)^ROR(e,11)^ROR(e,25)) + ((e&f)^(~e&g)) + K[i] + w[i];
        t2 = (ROR(a,2)^ROR(a,13)^ROR(a,22)) + ((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;st[5]+=f;st[6]+=g;st[7]+=h;
}

static uint32_t midstate[8], tailw[16], targ[8];
static int nbits, nthreads;
static volatile int found = 0;
static uint64_t found_nonce = 0;
static uint64_t total_tried = 0;
static pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;

static int prefix_ok(const uint32_t st[8]) {
    int full = nbits >> 3, rem = nbits & 7, i;
    uint8_t d[32], t[32];
    for (i = 0; i < 8; i++) {
        d[4*i]=st[i]>>24; d[4*i+1]=st[i]>>16; d[4*i+2]=st[i]>>8; d[4*i+3]=st[i];
        t[4*i]=targ[i]>>24; t[4*i+1]=targ[i]>>16; t[4*i+2]=targ[i]>>8; t[4*i+3]=targ[i];
    }
    for (i = 0; i < full; i++) if (d[i] != t[i]) return 0;
    if (rem) { uint8_t m = (uint8_t)(0xFF << (8-rem)); if ((d[full]&m) != (t[full]&m)) return 0; }
    return 1;
}

#define R32(x,n) _mm512_ror_epi32(x, n)

__attribute__((target("avx512f")))
static void *worker(void *arg) {
    uint64_t id = (uint64_t)(intptr_t)arg;
    uint64_t base = id << 56;              /* each thread owns a disjoint range */
    const __m512i lane = _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    __m512i wc[16];
    int i;
    for (i = 0; i < 16; i++) wc[i] = _mm512_set1_epi32((int)tailw[i]);
    const uint32_t m0 = (nbits >= 32) ? 0xFFFFFFFFu : ~0u << (32 - nbits);
    const __m512i t0 = _mm512_set1_epi32((int)(targ[0] & m0));
    const __m512i mv = _mm512_set1_epi32((int)m0);
    const __m512i h0 = _mm512_set1_epi32((int)midstate[0]);
    uint64_t local = 0;

    while (!found) {
        __m512i w[64], a,b,c,d,e,f,g,h;
        w[0] = _mm512_set1_epi32((int)(uint32_t)(base >> 32));
        w[1] = _mm512_add_epi32(_mm512_set1_epi32((int)(uint32_t)base), lane);
        for (i = 2; i < 16; i++) w[i] = wc[i];
        for (i = 16; i < 64; i++) {
            __m512i x = w[i-15], y = w[i-2];
            __m512i s0 = _mm512_xor_si512(_mm512_xor_si512(R32(x,7), R32(x,18)), _mm512_srli_epi32(x,3));
            __m512i s1 = _mm512_xor_si512(_mm512_xor_si512(R32(y,17), R32(y,19)), _mm512_srli_epi32(y,10));
            w[i] = _mm512_add_epi32(_mm512_add_epi32(s1, w[i-7]), _mm512_add_epi32(s0, w[i-16]));
        }
        a=_mm512_set1_epi32((int)midstate[0]); b=_mm512_set1_epi32((int)midstate[1]);
        c=_mm512_set1_epi32((int)midstate[2]); d=_mm512_set1_epi32((int)midstate[3]);
        e=_mm512_set1_epi32((int)midstate[4]); f=_mm512_set1_epi32((int)midstate[5]);
        g=_mm512_set1_epi32((int)midstate[6]); h=_mm512_set1_epi32((int)midstate[7]);
        for (i = 0; i < 64; i++) {
            __m512i S1 = _mm512_xor_si512(_mm512_xor_si512(R32(e,6), R32(e,11)), R32(e,25));
            __m512i ch = _mm512_ternarylogic_epi32(e, f, g, 0xCA);          /* (e&f)^(~e&g) */
            __m512i t1 = _mm512_add_epi32(_mm512_add_epi32(h, S1),
                         _mm512_add_epi32(ch, _mm512_add_epi32(_mm512_set1_epi32((int)K[i]), w[i])));
            __m512i S0 = _mm512_xor_si512(_mm512_xor_si512(R32(a,2), R32(a,13)), R32(a,22));
            __m512i mj = _mm512_ternarylogic_epi32(a, b, c, 0xE8);          /* maj */
            __m512i t2 = _mm512_add_epi32(S0, mj);
            h=g; g=f; f=e; e=_mm512_add_epi32(d,t1); d=c; c=b; b=a; a=_mm512_add_epi32(t1,t2);
        }
        __m512i out0 = _mm512_and_si512(_mm512_add_epi32(a, h0), mv);
        __mmask16 m = _mm512_cmpeq_epi32_mask(out0, t0);
        if (m) {   /* candidate on word 0: confirm the full prefix in scalar code */
            for (int j = 0; j < 16; j++) if (m & (1u << j)) {
                uint64_t n = base + j;
                uint32_t st[8], ww[16];
                memcpy(st, midstate, sizeof(st));
                memcpy(ww, tailw, sizeof(ww));
                ww[0] = (uint32_t)(n >> 32); ww[1] = (uint32_t)n;
                compress(st, ww);
                if (prefix_ok(st)) {
                    pthread_mutex_lock(&lk);
                    if (!found) { found_nonce = n; found = 1; }
                    pthread_mutex_unlock(&lk);
                }
            }
            if (found) break;
        }
        base += 16;
        if ((++local & 0xFFFFF) == 0) {
            pthread_mutex_lock(&lk);
            total_tried += 0x100000ULL * 16;
            if (id == 0) {
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                double el = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
                fprintf(stderr, "%.4g tries  %.0fs  %.0f Mtries/s  %.1f%% of expected\n",
                        (double)total_tried, el, total_tried / el / 1e6,
                        100.0 * total_tried / exp2((double)nbits));
                fflush(stderr);
            }
            pthread_mutex_unlock(&lk);
        }
    }
    pthread_mutex_lock(&lk); total_tried += (local & 0xFFFFF) * 16ULL; pthread_mutex_unlock(&lk);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s file targethex nbits nthreads\n", argv[0]); return 2; }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("open"); return 1; }
    fseek(fp, 0, SEEK_END); long L = ftell(fp); fseek(fp, 0, SEEK_SET);
    uint8_t *buf = malloc(L);
    if (fread(buf, 1, L, fp) != (size_t)L) { perror("read"); return 1; }
    fclose(fp);
    if (L % 64 != 8) { fprintf(stderr, "file length %ld is not 8 mod 64\n", L); return 1; }

    nbits = atoi(argv[3]); nthreads = atoi(argv[4]);
    uint8_t tb[32]; memset(tb, 0, 32);
    for (int i = 0; i < (nbits + 7) / 8; i++) {
        char s[3] = { argv[2][2*i], argv[2][2*i+1] ? argv[2][2*i+1] : '0', 0 };
        tb[i] = (uint8_t)strtol(s, NULL, 16);
    }
    if (nbits < 1 || nbits > 256) { fprintf(stderr, "nbits out of range\n"); return 1; }
    for (int i = 0; i < 8; i++)
        targ[i] = (tb[4*i]<<24)|(tb[4*i+1]<<16)|(tb[4*i+2]<<8)|tb[4*i+3];

    midstate[0]=0x6a09e667;midstate[1]=0xbb67ae85;midstate[2]=0x3c6ef372;midstate[3]=0xa54ff53a;
    midstate[4]=0x510e527f;midstate[5]=0x9b05688c;midstate[6]=0x1f83d9ab;midstate[7]=0x5be0cd19;
    for (long off = 0; off + 64 <= L - 8; off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i]=(buf[off+4*i]<<24)|(buf[off+4*i+1]<<16)|(buf[off+4*i+2]<<8)|buf[off+4*i+3];
        compress(midstate, w);
    }
    memset(tailw, 0, sizeof(tailw));
    tailw[2]  = 0x80000000u;
    tailw[14] = (uint32_t)(((uint64_t)L * 8) >> 32);
    tailw[15] = (uint32_t)((uint64_t)L * 8);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    start = t0;
    pthread_t th[64];
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, (void*)(intptr_t)i);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double dt = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    fprintf(stderr, "%.3g tries in %.1fs (%.1f Mtries/s)\n",
            (double)total_tried, dt, (double)total_tried/dt/1e6);
    printf("%016llx\n", (unsigned long long)found_nonce);
    return 0;
}
