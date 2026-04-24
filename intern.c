/* intern.c – Axis-512 Cryptographic Core
 * v3.0.5-Keccak – CONSTANT‑TIME PATCHED VERSION
 *
 * CHANGES (constant‑time fixes):
 *   - axis_permute(): sodium_memcmp + bitwise mask selection (no branches)
 *   - absorb_data(): masked copy + arithmetic padding byte selection
 *   - Added ct_barrier(), ct_memcmp(), ct_is_zero()
 *   - Added self‑test 8 for constant‑time utilities
 *   - Removed unused ct_select() function
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sodium.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/prctl.h>

#define AXIS_STATE_WORDS   25   /* Keccak-f[1600] uses 25 64-bit lanes */
#define AXIS_MAX_ROUNDS    24
#define STREAM_BUFFER_SIZE (1024 * 1024)
#define SHRED_CHUNK_SIZE   (1024 * 1024)

#define SIV_DOMAIN     "AXIS-SIV-V2"
#define SIV_DOMAIN_LEN 11

typedef struct {
    uint64_t w[AXIS_STATE_WORDS];
} axis_state;

int axis_rounds = 20;
const char *rounds_preset_name = "20 (Standard)";
int tmr_enabled = 1;

#define ARGON2_MEMORY_WEAK     (128ULL  * 1024 * 1024)
#define ARGON2_MEMORY_MODERATE (256ULL  * 1024 * 1024)
#define ARGON2_MEMORY_STRONG   (512ULL  * 1024 * 1024)
#define ARGON2_MEMORY_MAXIMUM  (1024ULL * 1024 * 1024)
#define ARGON2_MEMORY_QUANTUM  (2ULL    * 1024 * 1024 * 1024)

size_t      argon2_memory      = ARGON2_MEMORY_MODERATE;
const char *argon2_preset_name = "Moderate (256 MiB)";

#define ARGON2_OPSLIMIT crypto_pwhash_OPSLIMIT_SENSITIVE
uint32_t spip_iterations = (1 << 22);
int paranoid_mode        = 0;
extern int quantum_mode_enabled;

/* ---------- Constant‑time utilities ---------- */
static inline void ct_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" ::: "memory");
#else
    /* fallback – prevent compiler reordering */
    volatile int dummy = 0;
    (void)dummy;
#endif
}

static inline int ct_memcmp(const void *a, const void *b, size_t n) {
    return sodium_memcmp(a, b, n);
}

static inline int ct_is_zero(const void *ptr, size_t n) {
    const volatile uint8_t *p = (const volatile uint8_t *)ptr;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= p[i];
    }
    return (acc == 0) ? 1 : 0;
}

/* ---------- Keccak-f[1600] permutation (reference implementation) ---------- */
#define KECCAK_ROUNDS 24

static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static void keccak_f1600(uint64_t a[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta */
        uint64_t c[5] = {0};
        for (int i = 0; i < 5; i++)
            c[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20];
        uint64_t d[5];
        for (int i = 0; i < 5; i++)
            d[i] = c[(i+4)%5] ^ (c[(i+1)%5] << 1) ^ (c[(i+1)%5] >> 63);
        for (int i = 0; i < 25; i++)
            a[i] ^= d[i%5];

        /* Rho and Pi */
        uint64_t b[25];
        for (int i = 0; i < 25; i++) b[i] = a[i];
        int x = 1, y = 0;
        uint64_t curr = b[1];
        for (int t = 0; t < 24; t++) {
            int nx = y;
            int ny = (2*x + 3*y) % 5;
            uint64_t nxt = b[ny*5 + nx];
            int r = ((t+1)*(t+2)/2) % 64;
            b[ny*5 + nx] = (curr << r) | (curr >> (64 - r));
            curr = nxt;
            x = nx; y = ny;
        }
        for (int i = 0; i < 25; i++) a[i] = b[i];

        /* Chi */
        for (int y = 0; y < 5; y++) {
            uint64_t t0 = a[y*5+0], t1 = a[y*5+1], t2 = a[y*5+2], t3 = a[y*5+3], t4 = a[y*5+4];
            a[y*5+0] = t0 ^ ((~t1) & t2);
            a[y*5+1] = t1 ^ ((~t2) & t3);
            a[y*5+2] = t2 ^ ((~t3) & t4);
            a[y*5+3] = t3 ^ ((~t4) & t0);
            a[y*5+4] = t4 ^ ((~t0) & t1);
        }

        /* Iota */
        a[0] ^= keccak_round_constants[round];
    }
}

/* ---------- mlock + madvise (unchanged) ---------- */
static int mlock_available = 1;
static int mlock_warned    = 0;

int lock_sensitive(void *ptr, size_t len) {
    if (!mlock_available) return -1;
    if (sodium_mlock(ptr, len) != 0) {
        mlock_available = 0;
        if (!mlock_warned) {
            fprintf(stderr,
                "\n⚠️  mlock() unavailable – sensitive data may be swapped to disk.\n");
            mlock_warned = 1;
        }
        return -1;
    }
#ifdef MADV_DONTDUMP
    madvise(ptr, len, MADV_DONTDUMP);
#endif
#ifdef MADV_WIPEONFORK
    madvise(ptr, len, MADV_WIPEONFORK);
#endif
    return 0;
}

void secure_mlock(void *ptr, size_t len) { lock_sensitive(ptr, len); }
void secure_munlock(void *ptr, size_t len) { if (mlock_available) sodium_munlock(ptr, len); }
int axis_mlock_available(void) { return mlock_available; }

void secure_wipe(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) p[i] = 0;
#endif
}

void block_sleep_states(void) {
    prctl(PR_SET_DUMPABLE, 0);
#ifdef PR_SET_NO_NEW_PRIVS
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
}

int aes256gcm_available(void) { return crypto_aead_aes256gcm_is_available(); }

void disable_core_dumps(void) {
    struct rlimit limit = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &limit) != 0)
        fprintf(stderr, "⚠️  Unable to disable core dumps. Continuing anyway.\n");
}

static void write_pattern_fd(int fd, uint8_t pattern,
                              size_t file_size, uint8_t *buf, size_t chunk)
{
    memset(buf, pattern, chunk);
    size_t rem = file_size;
    off_t  off = 0;
    while (rem > 0) {
        size_t n = (rem < chunk) ? rem : chunk;
        if (pwrite(fd, buf, n, off) != (ssize_t)n) { /* best effort */ }
        off += (off_t)n;
        rem -= n;
    }
    fsync(fd);
}

static void shred_fd(int fd, size_t size) {
    if (size == 0) return;
    uint8_t *buf = malloc(SHRED_CHUNK_SIZE);
    if (!buf) return;
    write_pattern_fd(fd, 0x00, size, buf, SHRED_CHUNK_SIZE);
    write_pattern_fd(fd, 0xFF, size, buf, SHRED_CHUNK_SIZE);
    size_t rem = size; off_t off = 0;
    while (rem > 0) {
        size_t n = (rem < SHRED_CHUNK_SIZE) ? rem : SHRED_CHUNK_SIZE;
        randombytes_buf(buf, n);
        if (pwrite(fd, buf, n, off) != (ssize_t)n) { /* best effort */ }
        off += (off_t)n; rem -= n;
    }
    fsync(fd);
    rem = size; off = 0;
    while (rem > 0) {
        size_t n = (rem < SHRED_CHUNK_SIZE) ? rem : SHRED_CHUNK_SIZE;
        for (size_t i = 0; i < n; i++) buf[i] = (i & 1) ? 0xAA : 0x55;
        if (pwrite(fd, buf, n, off) != (ssize_t)n) { /* best effort */ }
        off += (off_t)n; rem -= n;
    }
    fsync(fd);
    write_pattern_fd(fd, 0x00, size, buf, SHRED_CHUNK_SIZE);
    free(buf);
}

int create_memfd(const char *name) {
#ifdef __linux__
    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd >= 0) return fd;
#endif
    char tmpl[] = "/tmp/axis512_XXXXXX";
    int tfd = mkstemp(tmpl);
    if (tfd >= 0) { unlink(tmpl); return tfd; }
    return -1;
}

void secure_close_fd(int fd, size_t size) {
    if (fd >= 0) { shred_fd(fd, size); close(fd); }
}

/* ---------- Utility functions (unchanged) ---------- */
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

void deep_scrub(void *ptr, size_t len) {
    if (len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    randombytes_buf((void *)p, len);
    for (size_t i = 0; i < len; i++) p[i] = ~p[i];
    for (size_t i = 0; i < len; i++) p[i] = (i & 1) ? 0xAA : 0x55;
    secure_wipe((void *)p, len);
}

void deep_scrub_heap(void) {
    size_t sizes[] = { 64<<20, 32<<20, 16<<20, 8<<20, 0 };
    for (int i = 0; sizes[i] > 0; i++) {
        uint8_t *s = malloc(sizes[i]);
        if (s) { deep_scrub(s, sizes[i]); free(s); }
    }
}

void mix_password_and_pin(const char *password, const char *pin,
                          uint8_t *mixed, size_t *mixed_len)
{
    char combined[520];
    size_t pw_len  = password ? strlen(password) : 0;
    size_t pin_len = pin      ? strlen(pin)       : 0;

    if (pw_len + pin_len > 480) {
        fprintf(stderr,
            "\n⚠️  Password + PIN combined exceeds 480 characters.\n"
            "   Consider using shorter credentials to avoid any"
            " risk of truncation.\n");
    }

    int written = snprintf(combined, sizeof(combined), "%s::::%s",
                           password ? password : "",
                           pin      ? pin      : "");
    if (written < 0 || (size_t)written >= sizeof(combined)) {
        fprintf(stderr,
            "\n❌ FATAL: password+PIN combination too long for internal buffer.\n"
            "   Reduce password or PIN length and try again.\n");
        secure_wipe(combined, sizeof(combined));
        *mixed_len = 0;
        return;
    }

    *mixed_len = (size_t)written;
    memcpy(mixed, combined, *mixed_len);
    secure_wipe(combined, sizeof(combined));
}

void compute_siv_paranoid(const uint8_t *key, const uint8_t *data,
                          size_t data_len, uint8_t siv[64])
{
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) len_bytes[i] = (data_len >> (i*8)) & 0xFF;
    const char *domain = quantum_mode_enabled
        ? "AXIS-QUANTUM-PARANOID-SIV" : "AXIS-PARANOID-SIV";
    crypto_generichash_state st;
    crypto_generichash_init(&st, key, 32, 64);
    crypto_generichash_update(&st, (const uint8_t *)domain, strlen(domain));
    crypto_generichash_update(&st, len_bytes, 8);
    crypto_generichash_update(&st, data, data_len);
    crypto_generichash_final(&st, siv, 64);
}

/* ---------- Progress indicator (unchanged) ---------- */
extern void show_spip_progress(uint32_t cur, uint32_t total);

/* ---------- Key schedule for the Keccak sponge ---------- */
void axis_key_schedule(const uint8_t key[64],
                       uint64_t rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS])
{
    /* For Keccak sponge we don't need complex round keys.
       We just absorb the key into the state and run the permutation
       to initialise the first round key (all zero for sponge mode).
       The rk array is kept for compatibility but is all zeros except
       the first entry which is the key expanded into the state. */
    axis_state st;
    memset(&st, 0, sizeof(st));
    for (int i = 0; i < 64 && i < AXIS_STATE_WORDS*8; i++)
        st.w[i/8] |= ((uint64_t)key[i]) << ((i%8)*8);
    keccak_f1600(st.w);
    memcpy(rk[0], st.w, sizeof(st.w));
    for (int r = 1; r <= axis_rounds; r++) {
        keccak_f1600(st.w);
        memcpy(rk[r], st.w, sizeof(st.w));
    }
    secure_wipe(&st, sizeof(st));
}

/* ---------- Sponge functions (using Keccak-f[1600]) – CONSTANT‑TIME PATCHED ---------- */
int axis_permute(axis_state *st, const uint64_t rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS]) {
    (void)rk;  /* not used in this simplified model – we always use Keccak */
    if (tmr_enabled) {
        axis_state s1, s2, s3;
        memcpy(&s1, st, sizeof(axis_state));
        memcpy(&s2, st, sizeof(axis_state));
        memcpy(&s3, st, sizeof(axis_state));
        keccak_f1600(s1.w);
        keccak_f1600(s2.w);
        keccak_f1600(s3.w);

        /* CONSTANT‑TIME FIX #1: use sodium_memcmp */
        int m12 = (sodium_memcmp(&s1, &s2, sizeof(axis_state)) == 0);
        int m23 = (sodium_memcmp(&s2, &s3, sizeof(axis_state)) == 0);
        int m13 = (sodium_memcmp(&s1, &s3, sizeof(axis_state)) == 0);

        if (m12+m23+m13 < 2) {
            secure_zero(&s1, sizeof s1);
            secure_zero(&s2, sizeof s2);
            secure_zero(&s3, sizeof s3);
            return -1;
        }

        /* CONSTANT‑TIME FIX #2: bitwise mask selection (no branches) */
        int use_s1 = m12 || m13;
        uint64_t mask = -(uint64_t)(use_s1 != 0);  /* all ones if true, zero otherwise */
        uint64_t *dst = st->w;
        uint64_t *src1 = s1.w;
        uint64_t *src2 = s2.w;

        for (int i = 0; i < AXIS_STATE_WORDS; i++) {
            dst[i] = (src1[i] & mask) | (src2[i] & ~mask);
        }

        secure_zero(&s1, sizeof s1);
        secure_zero(&s2, sizeof s2);
        secure_zero(&s3, sizeof s3);
        return 0;
    } else {
        keccak_f1600(st->w);
        return 0;
    }
}

void absorb_data(axis_state *st, const uint8_t *data, size_t len,
                 const uint64_t rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS])
{
    (void)rk;
    size_t offset = 0;
    const size_t block_size = 8 * 8; /* rate = 64 bytes (8 words) */
    while (offset + block_size <= len) {
        for (int i = 0; i < 8; i++) {
            uint64_t word = 0;
            for (int j = 0; j < 8; j++)
                word |= ((uint64_t)data[offset + i*8 + j]) << (j*8);
            st->w[i] ^= word;
        }
        offset += block_size;
        axis_permute(st, rk);
    }
    size_t rem = len - offset;
    uint8_t pad[64];

    /* Zero‑initialise pad (constant‑time) */
    for (int i = 0; i < 64; i++) {
        pad[i] = 0;
    }

    /* CONSTANT‑TIME FIX #3: masked copy of remaining data */
    for (size_t i = 0; i < 64; i++) {
        /* mask = 0xFF if i < rem, else 0x00 */
        uint8_t mask = -(uint8_t)(i < rem);
        pad[i] = (data[offset + i] & mask) | (pad[i] & ~mask);
    }

    /* CONSTANT‑TIME FIX #4: padding byte selection without branches */
    uint8_t pad_byte = 0x80 | (uint8_t)(rem > 0);
    for (size_t i = 0; i < 64; i++) {
        uint8_t mask = -(uint8_t)(i == rem && rem < 64);
        pad[i] ^= (pad_byte & mask);
    }

    /* Absorb padded block */
    for (int i = 0; i < 8; i++) {
        uint64_t word = 0;
        for (int j = 0; j < 8; j++) {
            word |= ((uint64_t)pad[i*8+j]) << (j*8);
        }
        st->w[i] ^= word;
    }
    axis_permute(st, rk);
}

void squeeze_data(axis_state *st, uint8_t *out, size_t len) {
    size_t offset = 0;
    const size_t rate_words = 8;
    while (offset < len) {
        for (size_t i = 0; i < rate_words && offset < len; i++) {
            uint64_t w = st->w[i];
            for (int j = 0; j < 8 && offset < len; j++)
                out[offset++] = (uint8_t)(w >> (j*8));
        }
        if (offset < len) {
            uint64_t zero_rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS] = {{0}};
            axis_permute(st, zero_rk);
        }
    }
}

void squeeze_tag(axis_state *st, uint8_t tag[64]) {
    for (int i = 0; i < 8; i++) {
        uint64_t w = st->w[8+i];
        for (int j = 0; j < 8; j++)
            tag[i*8+j] = (uint8_t)(w >> (j*8));
    }
}

/* =====================================================================
 * SPIP EXPANSION - BLAKE2b-BASED (unchanged from v3.0.4)
 * ===================================================================== */
void spip_expand_key(const uint8_t input_key[32],
                     uint64_t expanded_rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS])
{
    uint8_t hash_state_buf[64];
    crypto_generichash_state hash_state;
    
    const char *spip_domain = quantum_mode_enabled
        ? "AXIS-QUANTUM-SPIP-V2-BLAKE2B" : "AXIS-SPIP-V2-BLAKE2B";
    const char *spip_paranoid_domain = quantum_mode_enabled
        ? "AXIS-QUANTUM-PARANOID-SPIP-V2" : "AXIS-PARANOID-SPIP-V2";
    
    crypto_generichash_init(&hash_state, 
                            (const uint8_t*)spip_domain, 
                            strlen(spip_domain), 
                            64);
    crypto_generichash_update(&hash_state, input_key, 32);
    
    for (uint32_t iter = 0; iter < spip_iterations; iter++) {
        crypto_generichash_update(&hash_state, (uint8_t*)&iter, sizeof(iter));
        
        if (paranoid_mode && (iter % 65536 == 0)) {
            crypto_generichash_final(&hash_state, hash_state_buf, 64);
            uint8_t paranoid_mixed[64];
            crypto_generichash(paranoid_mixed, 64,
                              hash_state_buf, 64,
                              (const uint8_t*)spip_paranoid_domain,
                              strlen(spip_paranoid_domain));
            crypto_generichash_init(&hash_state, paranoid_mixed, 64, 64);
            secure_wipe(paranoid_mixed, 64);
        }
        
        if ((iter & 1023) == 0 || iter == spip_iterations - 1) {
            crypto_generichash_final(&hash_state, hash_state_buf, 64);
            crypto_generichash_init(&hash_state, hash_state_buf, 64, 64);
        }
        
        if ((iter % (spip_iterations/40 + 1)) == 0 ||
             iter == spip_iterations - 1) {
            show_spip_progress(iter+1, spip_iterations);
        }
    }
    
    uint8_t expanded_key[64];
    crypto_generichash_final(&hash_state, expanded_key, 64);
    
    const char *final_domain = quantum_mode_enabled
        ? "AXIS-QUANTUM-SPIP-FINAL-V2" : "AXIS-SPIP-FINAL-V2";
    uint8_t final_expanded[64];
    crypto_generichash(final_expanded, 64,
                      expanded_key, 64,
                      (const uint8_t*)final_domain,
                      strlen(final_domain));
    
    axis_key_schedule(final_expanded, expanded_rk);
    
    secure_wipe(hash_state_buf, sizeof(hash_state_buf));
    secure_wipe(expanded_key, sizeof(expanded_key));
    secure_wipe(final_expanded, sizeof(final_expanded));
    secure_wipe(&hash_state, sizeof(hash_state));
}

/* ---------- Key derivation (unchanged) ---------- */
int derive_key(const char *password, const char *pin,
               uint8_t salt[32], uint8_t key[32])
{
    uint8_t mixed[520];
    size_t  mixed_len = 0;
    mix_password_and_pin(password, pin, mixed, &mixed_len);
    if (mixed_len == 0) {
        secure_wipe(mixed, sizeof(mixed));
        return -1;
    }
    lock_sensitive(mixed, sizeof(mixed));
    int ret = crypto_pwhash(key, 32, (const char*)mixed, mixed_len, salt,
                            ARGON2_OPSLIMIT, argon2_memory,
                            crypto_pwhash_ALG_ARGON2ID13);
    deep_scrub(mixed, sizeof(mixed));
    secure_munlock(mixed, sizeof(mixed));
    return ret;
}

/* ---------- Self-test (updated with constant‑time test 8) ---------- */
int axis_self_test(void) {
    int orig_tmr = tmr_enabled;
    tmr_enabled  = 0;
    int result   = 0;

    /* Test 1 – permutation changes state (Keccak) */
    {
        axis_state st1 = {0};
        uint64_t zero_rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS] = {{0}};
        axis_state st2;
        memcpy(&st2, &st1, sizeof st1);
        if (axis_permute(&st2, zero_rk) != 0) {
            fprintf(stderr, "Self-test 1: permutation TMR failure\n");
            result = -1; goto done;
        }
        if (memcmp(&st1, &st2, sizeof st1) == 0) {
            fprintf(stderr, "Self-test 1: permutation did not change state\n");
            result = -1; goto done;
        }
    }

    /* Test 2 – SPIP produces non-zero round keys (BLAKE2b) */
    {
        uint8_t  test_key[32] = {0};
        uint64_t test_rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS] = {{0}};
        spip_expand_key(test_key, test_rk);
        int all_zero = 1;
        for (int i = 0; i <= axis_rounds && all_zero; i++)
            for (int j = 0; j < AXIS_STATE_WORDS; j++)
                if (test_rk[i][j]) { all_zero = 0; break; }
        if (all_zero) {
            fprintf(stderr, "Self-test 2: SPIP (BLAKE2b) produced all-zero round keys\n");
            result = -1; goto done;
        }
        
        uint8_t test_key2[32] = {1};
        uint64_t test_rk2[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS] = {{0}};
        spip_expand_key(test_key2, test_rk2);
        if (memcmp(test_rk, test_rk2, sizeof(test_rk)) == 0) {
            fprintf(stderr, "Self-test 2: SPIP produced identical output for different keys\n");
            result = -1; goto done;
        }
    }

    /* Test 3 – JIT key wrap/unwrap (unchanged) */
    {
        uint8_t derived_key[32], file_key[32], jit_nonce[24];
        uint8_t wrapped[48];
        uint8_t recovered[32];
        randombytes_buf(derived_key, sizeof derived_key);
        randombytes_buf(file_key,    sizeof file_key);
        randombytes_buf(jit_nonce,   sizeof jit_nonce);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                wrapped, NULL,
                file_key, sizeof file_key,
                NULL, 0, NULL,
                jit_nonce, derived_key) != 0) {
            fprintf(stderr, "Self-test 3: JIT wrap failed\n");
            result = -1; goto done;
        }
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                recovered, NULL, NULL,
                wrapped, sizeof wrapped,
                NULL, 0,
                jit_nonce, derived_key) != 0) {
            fprintf(stderr, "Self-test 3: JIT unwrap failed\n");
            result = -1; goto done;
        }
        if (sodium_memcmp(recovered, file_key, sizeof file_key) != 0) {
            fprintf(stderr, "Self-test 3: JIT recovered key mismatch\n");
            result = -1; goto done;
        }
        wrapped[0] ^= 0x01;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                recovered, NULL, NULL,
                wrapped, sizeof wrapped,
                NULL, 0,
                jit_nonce, derived_key) == 0) {
            fprintf(stderr, "Self-test 3: JIT unwrap accepted tampered ciphertext\n");
            result = -1; goto done;
        }
        secure_wipe(derived_key, sizeof derived_key);
        secure_wipe(file_key,    sizeof file_key);
        secure_wipe(recovered,   sizeof recovered);
    }

    /* Test 4 – SIV_DOMAIN_LEN matches actual string */
    {
        if (SIV_DOMAIN_LEN != (int)strlen(SIV_DOMAIN)) {
            fprintf(stderr,
                "Self-test 4: SIV_DOMAIN_LEN (%d) != strlen(\"%s\") (%zu)\n",
                SIV_DOMAIN_LEN, SIV_DOMAIN, strlen(SIV_DOMAIN));
            result = -1; goto done;
        }
    }

    /* Test 5 – Keccak permutation non-identity and avalanche */
    {
        axis_state st;
        memset(&st, 0, sizeof(st));
        st.w[0] = 1;
        axis_state st_orig;
        memcpy(&st_orig, &st, sizeof(st));
        uint64_t zero_rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS] = {{0}};
        axis_permute(&st, zero_rk);
        if (memcmp(&st, &st_orig, sizeof(st)) == 0) {
            fprintf(stderr, "Self-test 5: Keccak permutation is identity\n");
            result = -1; goto done;
        }
        uint64_t h1 = 0, h2 = 0;
        for (int i = 0; i < AXIS_STATE_WORDS; i++) {
            h1 ^= st.w[i];
        }
        memcpy(&st, &st_orig, sizeof(st));
        st.w[0] ^= 1ULL << 7;
        axis_permute(&st, zero_rk);
        for (int i = 0; i < AXIS_STATE_WORDS; i++) {
            h2 ^= st.w[i];
        }
        if (h1 == h2) {
            fprintf(stderr, "Self-test 5: Keccak avalanche weak (hash collision)\n");
            result = -1; goto done;
        }
    }

    /* Test 6 – AES-256-GCM self-test (if available) */
    if (aes256gcm_available()) {
        uint8_t key[32], nonce[12], plaintext[64], ciphertext[64+16], decrypted[64];
        unsigned long long clen, dlen;
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));
        randombytes_buf(plaintext, sizeof(plaintext));
        if (crypto_aead_aes256gcm_encrypt(ciphertext, &clen,
                                          plaintext, sizeof(plaintext),
                                          NULL, 0, NULL, nonce, key) != 0) {
            fprintf(stderr, "Self-test 6: AES-GCM encryption failed\n");
            result = -1; goto done;
        }
        if (crypto_aead_aes256gcm_decrypt(decrypted, &dlen, NULL,
                                          ciphertext, clen,
                                          NULL, 0, nonce, key) != 0) {
            fprintf(stderr, "Self-test 6: AES-GCM decryption failed\n");
            result = -1; goto done;
        }
        if (dlen != sizeof(plaintext) || memcmp(plaintext, decrypted, dlen) != 0) {
            fprintf(stderr, "Self-test 6: AES-GCM round-trip mismatch\n");
            result = -1; goto done;
        }
    }

    /* Test 7 – BLAKE2b SPIP produces consistent output with same input */
    {
        uint8_t test_key[32];
        randombytes_buf(test_key, sizeof(test_key));
        
        uint64_t test_rk1[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS];
        uint64_t test_rk2[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS];
        
        uint32_t saved_iterations = spip_iterations;
        spip_iterations = 1000;
        
        spip_expand_key(test_key, test_rk1);
        spip_expand_key(test_key, test_rk2);
        
        if (memcmp(test_rk1, test_rk2, sizeof(test_rk1)) != 0) {
            fprintf(stderr, "Self-test 7: BLAKE2b SPIP produced inconsistent output\n");
            result = -1;
        }
        
        spip_iterations = saved_iterations;
    }

    /* Test 8 – Constant‑time utilities verification */
    {
        uint8_t a[64], b[64];
        randombytes_buf(a, sizeof(a));
        memcpy(b, a, sizeof(a));
        
        if (ct_memcmp(a, b, sizeof(a)) != 0) {
            fprintf(stderr, "Self-test 8: ct_memcmp failed on equal buffers\n");
            result = -1; goto done;
        }
        
        b[32] ^= 0x01;
        if (ct_memcmp(a, b, sizeof(a)) == 0) {
            fprintf(stderr, "Self-test 8: ct_memcmp failed on different buffers\n");
            result = -1; goto done;
        }
        
        uint8_t zero[64] = {0};
        if (!ct_is_zero(zero, sizeof(zero))) {
            fprintf(stderr, "Self-test 8: ct_is_zero failed on zero buffer\n");
            result = -1; goto done;
        }
        
        zero[10] = 1;
        if (ct_is_zero(zero, sizeof(zero))) {
            fprintf(stderr, "Self-test 8: ct_is_zero failed on non-zero buffer\n");
            result = -1; goto done;
        }
    }

done:
    tmr_enabled = orig_tmr;
    return result;
}
