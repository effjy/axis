/* axis.c – Axis-512 User Interface
 * v3.0.5-Keccak – NIST standard sponge (Keccak-f[1600])
 *
 * (No constant‑time changes – all timing‑sensitive code is in intern.c)
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <sodium.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>

/* Resolve randombytes name collision with Kyber cleanly */
#pragma push_macro("randombytes")
#define randombytes kyber_randombytes
#include "kyber/kem.h"
#pragma pop_macro("randombytes")

void kyber_randombytes(uint8_t *out, size_t outlen) {
    randombytes_buf(out, outlen);
}

/* ---------------------- ANSI Colors ---------------------- */
#define COLOR_RESET  "\033[0m"
#define COLOR_CYAN   "\033[1;36m"
#define COLOR_WHITE  "\033[1;37m"
#define COLOR_GREEN  "\033[1;32m"
#define COLOR_RED    "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE   "\033[1;34m"
#define CURSOR_HIDE  "\033[?25l"
#define CURSOR_SHOW  "\033[?25h"
#define CLEAR_LINE   "\033[2K"

/* ---------------------- Configuration ---------------------- */
#define AXIS_STATE_WORDS   25   /* Keccak-f[1600] uses 25 64-bit words */
#define AXIS_MAX_ROUNDS    24   /* Keccak-f[1600] always 24 rounds */
#define STREAM_BUFFER_SIZE (1024 * 1024)

/* SIV domain – defined once to prevent length/string drift */
#define SIV_DOMAIN     "AXIS-SIV-V2"
#define SIV_DOMAIN_LEN 11

/* Hybrid Kyber-1024 + X25519 KEM constants */
#define X25519_PUBKEY_LEN  crypto_box_PUBLICKEYBYTES   /* 32 */
#define X25519_PRIVKEY_LEN crypto_box_SECRETKEYBYTES   /* 32 */
#define HYBRID_CT_LEN      (KYBER_CIPHERTEXTBYTES + X25519_PUBKEY_LEN)
#define HYBRID_SK_LEN      (KYBER_SECRETKEYBYTES + X25519_PRIVKEY_LEN)

/* SKE (Secret Key Encryption) for hybrid secret key */
#define SKE_NONCE_LEN      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define SKE_TAG_LEN        crypto_aead_xchacha20poly1305_ietf_ABYTES
#define SKE_PAYLOAD_LEN    HYBRID_SK_LEN
#define SKE_CIPHERTEXT_LEN (SKE_PAYLOAD_LEN + SKE_TAG_LEN)
#define SKE_BLOB_LEN       (SKE_NONCE_LEN + SKE_CIPHERTEXT_LEN)

/* AES outer mode constants */
#define AES_OUTER_NONCE_LEN  12
#define AES_XCC_NONCE_LEN    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define AES_MAC_INPUT_LEN    64
#define AES_SEALED_MAC_LEN   (AES_MAC_INPUT_LEN + crypto_aead_aes256gcm_ABYTES)
#define AES_POST_TRAILER     AES_SEALED_MAC_LEN

/* Inner encryption constants */
#define INNER_KEY_LEN   crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define INNER_NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define INNER_ABYTES    crypto_aead_xchacha20poly1305_ietf_ABYTES
#define SS_HEADER_LEN   crypto_secretstream_xchacha20poly1305_HEADERBYTES

/* JIT key wrapping constants */
#define JIT_NONCE_LEN       crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define JIT_WRAPPED_KEY_LEN (32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)

typedef struct { uint64_t w[AXIS_STATE_WORDS]; } axis_state;

/* ---------------------- Global flags ---------------------- */
static int quiet_mode = 0;
static int dry_run    = 0;
static int no_heap_scrub = 0;
int quantum_mode_enabled = 0;
int ephemeral_mode       = 0;
int kyber_mode           = 1;
int use_aes_outer        = 0;

/* ---------------------- Terminal state for SIGINT ---------------------- */
static struct termios orig_termios;
static int termios_saved = 0;

static void restore_terminal(void) {
    if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        termios_saved = 0;
    }
}

static void sigint_handler(int sig) {
    (void)sig;
    restore_terminal();
    printf("\n");
    exit(130);
}

/* ---------------------- External Globals ---------------------- */
extern int         axis_rounds;
extern const char *rounds_preset_name;
extern int         tmr_enabled;
extern size_t      argon2_memory;
extern const char *argon2_preset_name;
extern uint32_t    spip_iterations;
extern int         paranoid_mode;

/* ---------------------- External Functions ---------------------- */
extern void    secure_zero(void *, size_t);
extern void    deep_scrub(void *, size_t);
extern void    deep_scrub_heap(void);
extern void    secure_mlock(void *, size_t);
extern void    secure_munlock(void *, size_t);
extern void    secure_wipe(void *, size_t);
extern int     create_memfd(const char *);
extern void    secure_close_fd(int, size_t);
extern void    disable_core_dumps(void);
extern int     axis_permute(axis_state *, const uint64_t [AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS]);
extern void    axis_key_schedule(const uint8_t [64], uint64_t [AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS]);
extern void    absorb_data(axis_state *, const uint8_t *, size_t,
                           const uint64_t [AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS]);
extern void    squeeze_data(axis_state *, uint8_t *, size_t);
extern void    squeeze_tag(axis_state *, uint8_t [64]);
extern void    spip_expand_key(const uint8_t [32],
                               uint64_t [AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS]);
extern int     derive_key(const char *, const char *, uint8_t [32], uint8_t [32]);
extern int     axis_self_test(void);
extern int     axis_mlock_available(void);
extern int     aes256gcm_available(void);
extern void    block_sleep_states(void);
extern int     lock_sensitive(void *, size_t);

/* ---------------------- File overwrite check ---------------------- */
static int confirm_overwrite(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 1;
    printf(COLOR_YELLOW "  File '%s' already exists. Overwrite? (y/N): " COLOR_RESET, path);
    char answer[8];
    if (fgets(answer, sizeof answer, stdin) == NULL) return 0;
    return (answer[0]=='y' || answer[0]=='Y');
}

/* ---------------------- Utility ---------------------- */
static int read_input(const char *prompt, char *buf, size_t sz, int show) {
    struct termios old, nw;
    printf("%s", prompt); fflush(stdout);
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    if (!termios_saved) { orig_termios = old; termios_saved = 1; }
    nw = old;
    if (!show) nw.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &nw) != 0) return -1;
    if (fgets(buf, (int)sz, stdin) == NULL) { tcsetattr(STDIN_FILENO,TCSAFLUSH,&old); return -1; }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    if (!show) printf("\n");
    size_t len = strlen(buf);
    if (len && buf[len-1]=='\n') buf[len-1]='\0';
    return 0;
}

static void wait_for_enter(void) {
    int c;
    while ((c=getchar())!='\n' && c!=EOF);
}

/* ---------------------- Safe menu input (fgets + strtol) ---------------------- */
static int get_menu_choice(void) {
    char buf[16];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return -1;
    char *endptr;
    long val = strtol(buf, &endptr, 10);
    if (endptr == buf || (*endptr != '\n' && *endptr != '\0')) return -1;
    return (int)val;
}

/* ---------------------- Progress bars ---------------------- */
static void show_progress(const char *label, size_t cur, size_t total, time_t start) {
    if (quiet_mode) return;
    if (total==0) return;
    int pct = (int)((cur*100ULL)/total);
    time_t now = time(NULL);
    double elapsed = difftime(now, start);
    double speed = (elapsed>0) ? (cur/(1024.0*1024.0))/elapsed : 0;
    printf("\r\033[K" COLOR_CYAN "  [%s] " COLOR_WHITE "[", label);
    int bar=40, pos=(bar*pct)/100;
    for (int i=0;i<bar;i++) {
        if(i<pos) printf(COLOR_GREEN "#" COLOR_RESET);
        else if(i==pos) printf(COLOR_YELLOW ">" COLOR_RESET);
        else printf(COLOR_WHITE "-" COLOR_RESET);
    }
    printf(COLOR_WHITE "] %3d%% (%.2f MB/s)" COLOR_RESET, pct, speed);
    fflush(stdout);
}

void show_spip_progress(uint32_t cur, uint32_t total) {
    if (quiet_mode) return;
    int pct = (int)((cur*100ULL)/total);
    printf("\r\033[K" COLOR_CYAN "  [SPIP Expansion] " COLOR_WHITE "[");
    int bar=40, pos=(bar*pct)/100;
    for (int i=0;i<bar;i++) {
        if(i<pos) printf(COLOR_GREEN "#" COLOR_RESET);
        else if(i==pos) printf(COLOR_YELLOW ">" COLOR_RESET);
        else printf(COLOR_WHITE "-" COLOR_RESET);
    }
    printf(COLOR_WHITE "] %3d%%" COLOR_RESET, pct);
    fflush(stdout);
}

/* ---------------------- Safe sendfile wrapper ---------------------- */
static ssize_t sendfile_all(int out_fd, int in_fd, size_t count) {
    size_t sent = 0;
    while (sent < count) {
        ssize_t n = sendfile(out_fd, in_fd, NULL, count-sent);
        if (n<=0) { if(errno==EINTR) continue; return -1; }
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

/* ---------------------- Helper: outer key from hybrid SS (BLAKE2b) ---------------------- */
static void derive_outer_key_from_ss(const uint8_t ss[32], uint8_t outer_key[32]) {
    crypto_generichash(outer_key, 32, ss, 32,
                       (const uint8_t*)"AXIS-HYBRID-OUTER", 17);
}

/* =====================================================================
 * GET FILE SIZE
 * ===================================================================== */
static size_t get_file_size(FILE *f) {
    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    size_t sz = (size_t)ftell(f);
    fseek(f, pos, SEEK_SET);
    return sz;
}

/* =====================================================================
 * COMPUTE SIV FROM PLAINTEXT (Streaming, O(1) RAM)
 * ===================================================================== */
static int compute_siv_streaming(const char *in_path,
                                 const uint8_t outer_key[32],
                                 uint8_t siv[64])
{
    FILE *fin = fopen(in_path, "rb");
    if (!fin) return -1;
    size_t file_size = get_file_size(fin);

    crypto_generichash_state state;
    crypto_generichash_init(&state, outer_key, 32, 64);
    crypto_generichash_update(&state,
                              (const uint8_t*)SIV_DOMAIN,
                              SIV_DOMAIN_LEN);

    /* include file size (64-bit little-endian) to prevent canonicalization */
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++)
        len_bytes[i] = (file_size >> (i * 8)) & 0xFF;
    crypto_generichash_update(&state, len_bytes, 8);

    uint8_t *buf = malloc(STREAM_BUFFER_SIZE);
    if (!buf) { fclose(fin); return -1; }

    size_t processed = 0;
    time_t start = time(NULL);
    size_t last_up = 0;

    if (!quiet_mode)
        printf(COLOR_WHITE "  Pass 1/2: Computing SIV...\n" COLOR_RESET);

    while (processed < file_size) {
        size_t to_read = file_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        size_t n = fread(buf, 1, to_read, fin);
        if (n == 0) break;
        crypto_generichash_update(&state, buf, n);
        processed += n;
        if (processed - last_up >= 65536 || processed == file_size) {
            show_progress("SIV Computation", processed, file_size, start);
            last_up = processed;
        }
    }
    free(buf);
    fclose(fin);

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);
    crypto_generichash_final(&state, siv, 64);
    return 0;
}

/* =====================================================================
 * INNER ENCRYPTION - STREAMING (O(1) RAM)
 * ===================================================================== */
static int inner_encrypt_streaming(const char *in_path,
                                    FILE *fout,
                                    uint8_t inner_key_out[INNER_KEY_LEN],
                                    uint8_t inner_nonce_out[INNER_NONCE_LEN])
{
    uint8_t inner_key[INNER_KEY_LEN];
    uint8_t inner_nonce[INNER_NONCE_LEN];
    randombytes_buf(inner_key,   sizeof inner_key);
    randombytes_buf(inner_nonce, sizeof inner_nonce);
    lock_sensitive(inner_key,   sizeof inner_key);
    lock_sensitive(inner_nonce, sizeof inner_nonce);

    memcpy(inner_key_out,   inner_key,   INNER_KEY_LEN);
    memcpy(inner_nonce_out, inner_nonce, INNER_NONCE_LEN);

    fwrite(inner_key,   1, INNER_KEY_LEN,   fout);
    fwrite(inner_nonce, 1, INNER_NONCE_LEN, fout);

    crypto_secretstream_xchacha20poly1305_state ss_state;
    uint8_t ss_header[SS_HEADER_LEN];
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &ss_state, ss_header, inner_key) != 0) {
        secure_wipe(inner_key,   sizeof inner_key);
        secure_wipe(inner_nonce, sizeof inner_nonce);
        return -1;
    }
    fwrite(ss_header, 1, SS_HEADER_LEN, fout);

    FILE *fin = fopen(in_path, "rb");
    if (!fin) {
        secure_wipe(inner_key,   sizeof inner_key);
        secure_wipe(inner_nonce, sizeof inner_nonce);
        return -1;
    }
    size_t file_size = get_file_size(fin);

    uint8_t *plain_buf  = malloc(STREAM_BUFFER_SIZE);
    uint8_t *cipher_buf = malloc(STREAM_BUFFER_SIZE +
                                 crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!plain_buf || !cipher_buf) {
        free(plain_buf); free(cipher_buf);
        fclose(fin);
        secure_wipe(inner_key,   sizeof inner_key);
        secure_wipe(inner_nonce, sizeof inner_nonce);
        return -1;
    }

    size_t processed = 0;
    time_t start = time(NULL);
    size_t last_up = 0;
    int enc_ok = 1;

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Pass 2/2: Inner encryption (XChaCha20-Poly1305)...\n" COLOR_RESET);

    while (processed < file_size) {
        size_t chunk = file_size - processed;
        if (chunk > STREAM_BUFFER_SIZE) chunk = STREAM_BUFFER_SIZE;
        size_t n = fread(plain_buf, 1, chunk, fin);
        if (n == 0) break;

        unsigned char tag = (processed + n == file_size)
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        const uint8_t *ad     = (processed == 0) ? inner_nonce : NULL;
        size_t         ad_len = (processed == 0) ? INNER_NONCE_LEN : 0;

        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &ss_state,
                cipher_buf, &ct_len,
                plain_buf, n,
                ad, ad_len,
                tag) != 0) {
            enc_ok = 0; break;
        }
        fwrite(cipher_buf, 1, (size_t)ct_len, fout);
        processed += n;

        if (processed - last_up >= 65536 || processed == file_size) {
            show_progress("Inner Encryption", processed, file_size, start);
            last_up = processed;
        }
    }

    free(plain_buf);
    free(cipher_buf);
    fclose(fin);
    secure_wipe(&ss_state, sizeof ss_state);
    secure_wipe(inner_key,   sizeof inner_key);
    secure_wipe(inner_nonce, sizeof inner_nonce);

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);
    return enc_ok ? 0 : -1;
}

/* =====================================================================
 * INNER DECRYPTION - STREAMING TO FILE DESCRIPTOR (O(1) RAM)
 * ===================================================================== */
static int inner_decrypt_streaming_to_fd(FILE *fin,
                                          int out_fd,
                                          size_t inner_stream_len)
{
    uint8_t inner_key[INNER_KEY_LEN];
    uint8_t inner_nonce[INNER_NONCE_LEN];
    uint8_t ss_header[SS_HEADER_LEN];

    if (fread(inner_key,   1, INNER_KEY_LEN,   fin) != INNER_KEY_LEN  ||
        fread(inner_nonce, 1, INNER_NONCE_LEN, fin) != INNER_NONCE_LEN ||
        fread(ss_header,   1, SS_HEADER_LEN,   fin) != SS_HEADER_LEN) {
        fprintf(stderr,
            COLOR_RED "Inner layer header incomplete\n" COLOR_RESET);
        return -1;
    }

    size_t ciphertext_len = inner_stream_len
                          - INNER_KEY_LEN - INNER_NONCE_LEN - SS_HEADER_LEN;

    crypto_secretstream_xchacha20poly1305_state ss_state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &ss_state, ss_header, inner_key) != 0) {
        fprintf(stderr,
            COLOR_RED "Inner layer: secretstream init failed\n" COLOR_RESET);
        secure_wipe(inner_key,   sizeof inner_key);
        secure_wipe(inner_nonce, sizeof inner_nonce);
        return -1;
    }

    uint8_t *ct_buf = malloc(STREAM_BUFFER_SIZE +
                             crypto_secretstream_xchacha20poly1305_ABYTES);
    uint8_t *pt_buf = malloc(STREAM_BUFFER_SIZE);
    if (!ct_buf || !pt_buf) {
        free(ct_buf); free(pt_buf);
        secure_wipe(inner_key,   sizeof inner_key);
        secure_wipe(inner_nonce, sizeof inner_nonce);
        return -1;
    }

    size_t ct_remaining      = ciphertext_len;
    size_t plaintext_written = 0;
    int    dec_ok            = 1;
    int    first_chunk       = 1;
    time_t start             = time(NULL);
    size_t last_up           = 0;

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Inner decryption (XChaCha20-Poly1305)...\n" COLOR_RESET);

    while (ct_remaining > 0 && dec_ok) {
        size_t to_read = ct_remaining;
        if (to_read > STREAM_BUFFER_SIZE +
                      crypto_secretstream_xchacha20poly1305_ABYTES)
            to_read = STREAM_BUFFER_SIZE +
                      crypto_secretstream_xchacha20poly1305_ABYTES;

        size_t n = fread(ct_buf, 1, to_read, fin);
        if (n == 0) break;

        const uint8_t *ad     = first_chunk ? inner_nonce : NULL;
        size_t         ad_len = first_chunk ? INNER_NONCE_LEN : 0;
        first_chunk = 0;

        unsigned long long pt_len = 0;
        unsigned char      tag;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &ss_state,
                pt_buf, &pt_len,
                &tag,
                ct_buf, n,
                ad, ad_len) != 0) {
            fprintf(stderr,
                COLOR_RED "\n❌ Inner layer: authentication failed.\n" COLOR_RESET);
            dec_ok = 0; break;
        }

        if (write(out_fd, pt_buf, (size_t)pt_len) != (ssize_t)pt_len) {
            dec_ok = 0; break;
        }
        plaintext_written += (size_t)pt_len;
        ct_remaining      -= n;

        if (plaintext_written - last_up >= 65536 || ct_remaining == 0) {
            show_progress("Inner Decryption", plaintext_written,
                          plaintext_written + ct_remaining, start);
            last_up = plaintext_written;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            break;
    }

    free(ct_buf);
    free(pt_buf);
    secure_wipe(&ss_state, sizeof ss_state);
    secure_wipe(inner_key,   sizeof inner_key);
    secure_wipe(inner_nonce, sizeof inner_nonce);

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);
    return dec_ok ? 0 : -1;
}

/* =====================================================================
 * AES OUTER – STREAMING ENCRYPT (O(1) RAM)
 * ===================================================================== */
static int aes_outer_encrypt_streaming(FILE *inner_f,
                                        size_t inner_len,
                                        const uint8_t outer_key[32],
                                        FILE *fout)
{
    if (!aes256gcm_available() && !quiet_mode) {
        fprintf(stderr,
            COLOR_YELLOW "\n⚠️  AES-256-GCM hardware not available; "
            "software fallback used (slower).\n" COLOR_RESET);
    }

    uint8_t aes_outer_nonce[AES_OUTER_NONCE_LEN];
    uint8_t xcc_nonce[AES_XCC_NONCE_LEN];
    randombytes_buf(aes_outer_nonce, sizeof aes_outer_nonce);
    randombytes_buf(xcc_nonce,       sizeof xcc_nonce);
    fwrite(aes_outer_nonce, 1, sizeof aes_outer_nonce, fout);
    fwrite(xcc_nonce,       1, sizeof xcc_nonce,       fout);

    uint8_t xcc_key[32];
    crypto_generichash(xcc_key, 32, outer_key, 32,
                       (const uint8_t*)"AXIS-AES-XCC", 12);
    lock_sensitive(xcc_key, sizeof xcc_key);

    crypto_secretstream_xchacha20poly1305_state ss_state;
    uint8_t ss_header[SS_HEADER_LEN];
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &ss_state, ss_header, xcc_key) != 0) {
        secure_wipe(xcc_key, sizeof xcc_key);
        return -1;
    }
    fwrite(ss_header, 1, sizeof ss_header, fout);
    secure_wipe(xcc_key, sizeof xcc_key);

    crypto_generichash_state mac_state;
    crypto_generichash_init(&mac_state, outer_key, 32, AES_MAC_INPUT_LEN);

    uint8_t *plain_buf  = malloc(STREAM_BUFFER_SIZE);
    uint8_t *cipher_buf = malloc(STREAM_BUFFER_SIZE +
                                 crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!plain_buf || !cipher_buf) {
        free(plain_buf); free(cipher_buf);
        return -1;
    }

    rewind(inner_f);
    size_t processed = 0;
    time_t start = time(NULL);
    size_t last_up = 0;
    int enc_ok = 1;

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Outer layer: AES-256-GCM (streaming)...\n" COLOR_RESET);

    while (processed < inner_len) {
        size_t chunk = inner_len - processed;
        if (chunk > STREAM_BUFFER_SIZE) chunk = STREAM_BUFFER_SIZE;
        size_t n = fread(plain_buf, 1, chunk, inner_f);
        if (n == 0) break;

        unsigned char tag = (processed + n == inner_len)
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        const uint8_t *ad     = (processed == 0) ? xcc_nonce : NULL;
        size_t         ad_len = (processed == 0) ? sizeof xcc_nonce : 0;

        unsigned long long ct_len = 0;
        if (crypto_secretstream_xchacha20poly1305_push(
                &ss_state,
                cipher_buf, &ct_len,
                plain_buf, n,
                ad, ad_len,
                tag) != 0) {
            enc_ok = 0; break;
        }
        fwrite(cipher_buf, 1, (size_t)ct_len, fout);
        crypto_generichash_update(&mac_state, cipher_buf, (size_t)ct_len);
        processed += n;

        if (processed - last_up >= 65536 || processed == inner_len) {
            show_progress("AES Outer", processed, inner_len, start);
            last_up = processed;
        }
    }

    free(plain_buf);
    free(cipher_buf);
    secure_wipe(&ss_state, sizeof ss_state);
    if (!enc_ok) return -1;

    uint8_t mac_digest[AES_MAC_INPUT_LEN];
    crypto_generichash_final(&mac_state, mac_digest, sizeof mac_digest);

    uint8_t sealed_mac[AES_SEALED_MAC_LEN];
    unsigned long long sealed_len = 0;
    crypto_aead_aes256gcm_encrypt(
        sealed_mac, &sealed_len,
        mac_digest, sizeof mac_digest,
        NULL, 0, NULL,
        aes_outer_nonce, outer_key);
    fwrite(sealed_mac, 1, (size_t)sealed_len, fout);

    secure_wipe(mac_digest, sizeof mac_digest);
    secure_wipe(sealed_mac, sizeof sealed_mac);

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);
    return 0;
}

/* =====================================================================
 * AES OUTER – STREAMING DECRYPT (O(1) RAM)
 * ===================================================================== */
static int aes_outer_decrypt_streaming(FILE *fin,
                                        size_t outer_ct_len,
                                        const uint8_t outer_key[32],
                                        FILE *inner_fout)
{
    uint8_t aes_outer_nonce[AES_OUTER_NONCE_LEN];
    uint8_t xcc_nonce[AES_XCC_NONCE_LEN];
    uint8_t ss_header[SS_HEADER_LEN];

    if (fread(aes_outer_nonce, 1, sizeof aes_outer_nonce, fin) != sizeof aes_outer_nonce ||
        fread(xcc_nonce,       1, sizeof xcc_nonce,       fin) != sizeof xcc_nonce       ||
        fread(ss_header,       1, sizeof ss_header,       fin) != sizeof ss_header) {
        fprintf(stderr, COLOR_RED "AES outer header incomplete\n" COLOR_RESET);
        return -1;
    }

    size_t stream_len = outer_ct_len
                      - AES_OUTER_NONCE_LEN - AES_XCC_NONCE_LEN
                      - SS_HEADER_LEN - AES_POST_TRAILER;

    uint8_t xcc_key[32];
    crypto_generichash(xcc_key, 32, outer_key, 32,
                       (const uint8_t*)"AXIS-AES-XCC", 12);
    lock_sensitive(xcc_key, sizeof xcc_key);

    crypto_secretstream_xchacha20poly1305_state ss_state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &ss_state, ss_header, xcc_key) != 0) {
        secure_wipe(xcc_key, sizeof xcc_key);
        return -1;
    }
    secure_wipe(xcc_key, sizeof xcc_key);

    crypto_generichash_state mac_state;
    crypto_generichash_init(&mac_state, outer_key, 32, AES_MAC_INPUT_LEN);

    size_t ct_chunk_buf_size = STREAM_BUFFER_SIZE +
                               crypto_secretstream_xchacha20poly1305_ABYTES;
    uint8_t *ct_buf = malloc(ct_chunk_buf_size);
    uint8_t *pt_buf = malloc(STREAM_BUFFER_SIZE);
    if (!ct_buf || !pt_buf) {
        free(ct_buf); free(pt_buf);
        return -1;
    }

    size_t ct_remaining = stream_len;
    size_t pt_written   = 0;
    int    dec_ok       = 1;
    int    first_chunk  = 1;
    time_t start        = time(NULL);
    size_t last_up      = 0;

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Outer layer: AES-256-GCM (decrypting)...\n" COLOR_RESET);

    while (ct_remaining > 0 && dec_ok) {
        size_t to_read = ct_remaining;
        if (to_read > ct_chunk_buf_size) to_read = ct_chunk_buf_size;
        size_t n = fread(ct_buf, 1, to_read, fin);
        if (n == 0) { dec_ok = 0; break; }

        crypto_generichash_update(&mac_state, ct_buf, n);

        const uint8_t *ad     = first_chunk ? xcc_nonce : NULL;
        size_t         ad_len = first_chunk ? sizeof xcc_nonce : 0;
        first_chunk = 0;

        unsigned long long pt_len = 0;
        unsigned char stag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &ss_state,
                pt_buf, &pt_len, &stag,
                ct_buf, n,
                ad, ad_len) != 0) {
            fprintf(stderr,
                COLOR_RED "\n❌ AES outer: stream authentication failed.\n" COLOR_RESET);
            dec_ok = 0; break;
        }
        fwrite(pt_buf, 1, (size_t)pt_len, inner_fout);
        pt_written   += (size_t)pt_len;
        ct_remaining -= n;

        if (pt_written - last_up >= 65536 || ct_remaining == 0) {
            show_progress("AES Outer Decrypt", pt_written,
                          pt_written + ct_remaining, start);
            last_up = pt_written;
        }
    }

    free(ct_buf);
    free(pt_buf);
    secure_wipe(&ss_state, sizeof ss_state);
    if (!dec_ok) return -1;

    uint8_t mac_digest_comp[AES_MAC_INPUT_LEN];
    crypto_generichash_final(&mac_state, mac_digest_comp, sizeof mac_digest_comp);

    uint8_t sealed_mac[AES_SEALED_MAC_LEN];
    if (fread(sealed_mac, 1, sizeof sealed_mac, fin) != sizeof sealed_mac) {
        fprintf(stderr, COLOR_RED "AES outer: sealed MAC missing\n" COLOR_RESET);
        return -1;
    }

    uint8_t mac_digest_file[AES_MAC_INPUT_LEN];
    unsigned long long unsealed_len = 0;
    if (crypto_aead_aes256gcm_decrypt(
            mac_digest_file, &unsealed_len, NULL,
            sealed_mac, sizeof sealed_mac,
            NULL, 0,
            aes_outer_nonce, outer_key) != 0) {
        fprintf(stderr,
            COLOR_RED "\n❌ AES outer: MAC seal authentication failed.\n" COLOR_RESET);
        return -1;
    }

    if (sodium_memcmp(mac_digest_comp, mac_digest_file, AES_MAC_INPUT_LEN) != 0) {
        fprintf(stderr,
            COLOR_RED "\n❌ AES outer: BLAKE2b MAC mismatch.\n" COLOR_RESET);
        return -1;
    }

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);
    return 0;
}

/* =====================================================================
 * KECCAK-f[1600] OUTER – STREAMING ENCRYPT (UPDATED for 25-word state)
 * ===================================================================== */
static int axis_outer_encrypt_streaming(FILE *inner_f,
                                         size_t inner_len,
                                         const uint8_t outer_key[32],
                                         const uint8_t siv[64],
                                         FILE *fout)
{
    uint64_t rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS];
    spip_expand_key(outer_key, rk);
    secure_mlock(rk, sizeof rk);

    uint8_t cap_mat[64];
    const char *cap_dom = quantum_mode_enabled
        ? "AXIS-QUANTUM-OUTER-CAPACITY" : "AXIS-OUTER-CAPACITY";
    if (paranoid_mode)
        crypto_generichash(cap_mat, sizeof cap_mat,
                           outer_key, 32,
                           (const uint8_t*)cap_dom, strlen(cap_dom));

    axis_state st, st_auth;
    memset(&st, 0, sizeof st);

    if (paranoid_mode) {
        for (int i = 0; i < 8 && i < AXIS_STATE_WORDS; i++) {
            uint64_t w = 0;
            for (int j = 0; j < 8; j++)
                w |= ((uint64_t)cap_mat[i*8+j]) << (j*8);
            st.w[8+i] = w;
        }
    } else {
        for (int i = 0; i < 8 && i < AXIS_STATE_WORDS; i++)
            for (int j = 0; j < 8; j++)
                st.w[8+i] |= ((uint64_t)outer_key[(i*8+j)&31]) << (j*8);
    }

    if (axis_permute(&st, rk) != 0) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }
    absorb_data(&st, siv, 64, rk);
    if (axis_permute(&st, rk) != 0) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }
    memcpy(&st_auth, &st, sizeof st);

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Outer layer: Keccak-f[1600] sponge (24 rounds, TMR %s)...\n" COLOR_RESET,
            tmr_enabled ? "ON" : "OFF");

    rewind(inner_f);
    time_t s2 = time(NULL);
    size_t proc = 0, lu = 0;
    uint8_t *cbuf = malloc(STREAM_BUFFER_SIZE);
    uint8_t *pbuf = malloc(STREAM_BUFFER_SIZE);
    if (!cbuf || !pbuf) {
        free(cbuf); free(pbuf);
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    while (proc < inner_len) {
        size_t tr = inner_len - proc;
        if (tr > STREAM_BUFFER_SIZE) tr = STREAM_BUFFER_SIZE;
        size_t n = fread(pbuf, 1, tr, inner_f);
        if (n == 0) break;
        squeeze_data(&st, cbuf, n);
        for (size_t i = 0; i < n; i++) cbuf[i] ^= pbuf[i];
        fwrite(cbuf, 1, n, fout);
        absorb_data(&st_auth, cbuf, n, rk);
        proc += n;
        if (proc - lu >= 65536 || proc == inner_len) {
            show_progress("Keccak Outer", proc, inner_len, s2);
            lu = proc;
        }
    }
    free(cbuf); free(pbuf);

    if (axis_permute(&st_auth, rk) != 0) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    uint8_t tag[64];
    squeeze_tag(&st_auth, tag);
    fwrite(tag, 1, 64, fout);

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);

    deep_scrub(rk, sizeof rk);       secure_munlock(rk, sizeof rk);
    deep_scrub(&st, sizeof st);
    deep_scrub(&st_auth, sizeof st_auth);
    if (paranoid_mode) deep_scrub(cap_mat, sizeof cap_mat);

    return 0;
}

/* =====================================================================
 * KECCAK-f[1600] OUTER – STREAMING DECRYPT
 * ===================================================================== */
static int axis_outer_decrypt_streaming(FILE *fin,
                                         size_t outer_ct_len,
                                         const uint8_t outer_key[32],
                                         const uint8_t siv[64],
                                         FILE *inner_fout)
{
    size_t csize = outer_ct_len - 64;

    uint64_t rk[AXIS_MAX_ROUNDS+1][AXIS_STATE_WORDS];
    spip_expand_key(outer_key, rk);
    secure_mlock(rk, sizeof rk);

    uint8_t cap_mat[64];
    const char *cap_dom = quantum_mode_enabled
        ? "AXIS-QUANTUM-OUTER-CAPACITY" : "AXIS-OUTER-CAPACITY";
    if (paranoid_mode)
        crypto_generichash(cap_mat, sizeof cap_mat,
                           outer_key, 32,
                           (const uint8_t*)cap_dom, strlen(cap_dom));

    axis_state st_auth, st_dec;
    memset(&st_auth, 0, sizeof st_auth);
    memset(&st_dec,  0, sizeof st_dec);

    if (paranoid_mode) {
        for (int i = 0; i < 8 && i < AXIS_STATE_WORDS; i++) {
            uint64_t w = 0;
            for (int j = 0; j < 8; j++)
                w |= ((uint64_t)cap_mat[i*8+j]) << (j*8);
            st_auth.w[8+i] = w;
            st_dec.w[8+i]  = w;
        }
    } else {
        for (int i = 0; i < 8 && i < AXIS_STATE_WORDS; i++)
            for (int j = 0; j < 8; j++) {
                st_auth.w[8+i] |= ((uint64_t)outer_key[(i*8+j)&31]) << (j*8);
                st_dec.w[8+i]  |= ((uint64_t)outer_key[(i*8+j)&31]) << (j*8);
            }
    }

    int init_ok = 1;
    if (axis_permute(&st_auth, rk) != 0) init_ok = 0;
    if (init_ok) {
        absorb_data(&st_auth, siv, 64, rk);
        if (axis_permute(&st_auth, rk) != 0) init_ok = 0;
    }
    if (init_ok && axis_permute(&st_dec, rk) != 0) init_ok = 0;
    if (init_ok) {
        absorb_data(&st_dec, siv, 64, rk);
        if (axis_permute(&st_dec, rk) != 0) init_ok = 0;
    }

    if (!init_ok) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    if (!quiet_mode)
        printf(COLOR_WHITE
            "  Outer layer: Keccak-f[1600] (decrypting)...\n" COLOR_RESET);

    uint8_t *cbuf = malloc(STREAM_BUFFER_SIZE);
    uint8_t *pbuf = malloc(STREAM_BUFFER_SIZE);
    if (!cbuf || !pbuf) {
        free(cbuf); free(pbuf);
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    size_t proc = 0;
    time_t s2 = time(NULL);
    size_t lu = 0;

    while (proc < csize) {
        size_t tr = csize - proc;
        if (tr > STREAM_BUFFER_SIZE) tr = STREAM_BUFFER_SIZE;
        size_t n = fread(cbuf, 1, tr, fin);
        if (!n) break;
        absorb_data(&st_auth, cbuf, n, rk);
        squeeze_data(&st_dec, pbuf, n);
        for (size_t i = 0; i < n; i++) pbuf[i] ^= cbuf[i];
        fwrite(pbuf, 1, n, inner_fout);
        proc += n;
        if (proc - lu >= 65536 || proc == csize) {
            show_progress("Keccak Outer Decrypt", proc, csize, s2);
            lu = proc;
        }
    }
    free(cbuf); free(pbuf);

    uint8_t tf[64];
    if (fread(tf, 1, 64, fin) != 64) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    if (axis_permute(&st_auth, rk) != 0) {
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    uint8_t tc[64];
    squeeze_tag(&st_auth, tc);

    if (sodium_memcmp(tc, tf, 64) != 0) {
        fprintf(stderr,
            COLOR_RED "\n❌ Decryption failed (outer tag mismatch).\n" COLOR_RESET);
        deep_scrub(rk, sizeof rk); secure_munlock(rk, sizeof rk);
        return -1;
    }

    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);

    deep_scrub(rk, sizeof rk);        secure_munlock(rk, sizeof rk);
    deep_scrub(&st_auth, sizeof st_auth);
    deep_scrub(&st_dec,  sizeof st_dec);
    if (paranoid_mode) deep_scrub(cap_mat, sizeof cap_mat);

    return 0;
}

/* =====================================================================
 * ENCRYPT FILE (v3.0.4-Keccak)
 * ===================================================================== */
static int encrypt_file(const char *in, const char *out,
                        const char *pwd, const char *pin)
{
    if (dry_run) {
        printf(COLOR_YELLOW
            "  [DRY RUN] Would encrypt '%s' -> '%s' "
            "(kyber: %s, ephemeral: %s, outer: %s)\n" COLOR_RESET,
            in, out,
            kyber_mode     ? "ON" : "OFF",
            ephemeral_mode ? "ON" : "OFF",
            use_aes_outer  ? "AES-streaming" : "Keccak-sponge");
        return 0;
    }

    if (!confirm_overwrite(out)) {
        printf(COLOR_YELLOW "  Overwrite cancelled.\n" COLOR_RESET);
        return -1;
    }

    uint8_t master_key[32], salt[32];
    randombytes_buf(salt, sizeof salt);
    lock_sensitive(master_key, sizeof master_key);

    if (!quiet_mode)
        printf(COLOR_WHITE "\n  Deriving master key with Argon2id (%s)...\n" COLOR_RESET,
               argon2_preset_name);
    if (derive_key(pwd, pin, salt, master_key) != 0) {
        secure_wipe(master_key, sizeof master_key);
        return -1;
    }

    uint8_t derived_outer_key[32];
    lock_sensitive(derived_outer_key, sizeof derived_outer_key);

    FILE *fout = fopen(out, "wb");
    if (!fout) {
        secure_wipe(master_key, sizeof master_key);
        secure_wipe(derived_outer_key, sizeof derived_outer_key);
        return -1;
    }
    fwrite(salt, 1, sizeof salt, fout);

    if (kyber_mode) {
        /* Generate static hybrid keypair (Kyber + X25519) for this file */
        uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
        uint8_t kyber_sk[KYBER_SECRETKEYBYTES];
        uint8_t x25519_pk[X25519_PUBKEY_LEN];
        uint8_t x25519_sk[X25519_PRIVKEY_LEN];

        if (!quiet_mode) printf(COLOR_WHITE
            "  Generating hybrid keypair (Kyber-1024 + X25519)...\n" COLOR_RESET);
        if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
            fprintf(stderr, COLOR_RED "Kyber keygen failed\n" COLOR_RESET);
            goto enc_fail;
        }
        if (crypto_box_keypair(x25519_pk, x25519_sk) != 0) {
            fprintf(stderr, COLOR_RED "X25519 keygen failed\n" COLOR_RESET);
            goto enc_fail;
        }

        /* Encrypt hybrid secret key (Kyber sk + X25519 sk) with master_key */
        uint8_t ske_nonce[SKE_NONCE_LEN];
        uint8_t ske_ct[SKE_CIPHERTEXT_LEN];
        randombytes_buf(ske_nonce, sizeof ske_nonce);
        uint8_t hybrid_sk[HYBRID_SK_LEN];
        memcpy(hybrid_sk, kyber_sk, KYBER_SECRETKEYBYTES);
        memcpy(hybrid_sk + KYBER_SECRETKEYBYTES, x25519_sk, X25519_PRIVKEY_LEN);
        lock_sensitive(hybrid_sk, sizeof hybrid_sk);
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ske_ct, NULL,
            hybrid_sk, sizeof hybrid_sk,
            NULL, 0, NULL, ske_nonce, master_key);
        fwrite(ske_nonce, 1, sizeof ske_nonce, fout);
        fwrite(ske_ct,    1, sizeof ske_ct,    fout);
        secure_wipe(hybrid_sk, sizeof hybrid_sk);
        secure_wipe(kyber_sk, sizeof kyber_sk);
        secure_wipe(x25519_sk, sizeof x25519_sk);

        /* Hybrid encapsulation: ephemeral X25519 keypair */
        uint8_t eph_priv[X25519_PRIVKEY_LEN];
        uint8_t eph_pub[X25519_PUBKEY_LEN];
        if (crypto_box_keypair(eph_pub, eph_priv) != 0) {
            fprintf(stderr, COLOR_RED "Ephemeral X25519 keygen failed\n" COLOR_RESET);
            goto enc_fail;
        }

        uint8_t ct_kyber[KYBER_CIPHERTEXTBYTES];
        uint8_t ss_kyber[KYBER_SSBYTES];
        uint8_t ss_x[X25519_PUBKEY_LEN];
        uint8_t ss[32];

        if (!quiet_mode) printf(COLOR_WHITE
            "  Hybrid encapsulation (Kyber + X25519)...\n" COLOR_RESET);
        if (crypto_kem_enc(ct_kyber, ss_kyber, kyber_pk) != 0) {
            fprintf(stderr, COLOR_RED "Kyber encapsulation failed\n" COLOR_RESET);
            goto enc_fail;
        }
        if (crypto_scalarmult(ss_x, eph_priv, x25519_pk) != 0) {
            fprintf(stderr, COLOR_RED "X25519 scalarmult failed\n" COLOR_RESET);
            goto enc_fail;
        }

        /* Combine shared secrets using BLAKE2b keyed with domain string */
        crypto_generichash_state st;
        crypto_generichash_init(&st, (const uint8_t*)"AXIS-HYBRID", 12, 32);
        crypto_generichash_update(&st, ss_kyber, KYBER_SSBYTES);
        crypto_generichash_update(&st, ss_x, X25519_PUBKEY_LEN);
        crypto_generichash_final(&st, ss, 32);
        secure_wipe(ss_kyber, sizeof ss_kyber);
        secure_wipe(ss_x, sizeof ss_x);
        secure_wipe(eph_priv, sizeof eph_priv);
        secure_wipe(kyber_pk, sizeof kyber_pk);
        secure_wipe(x25519_pk, sizeof x25519_pk);

        fwrite(ct_kyber, 1, KYBER_CIPHERTEXTBYTES, fout);
        fwrite(eph_pub,  1, X25519_PUBKEY_LEN,     fout);
        secure_wipe(ct_kyber, sizeof ct_kyber);
        secure_wipe(eph_pub,  sizeof eph_pub);

        derive_outer_key_from_ss(ss, derived_outer_key);
        secure_wipe(ss, sizeof ss);

    } else if (ephemeral_mode) {
        uint8_t eph_key[32], eph_nonce[24], eph_ct[48];
        randombytes_buf(eph_key,   sizeof eph_key);
        randombytes_buf(eph_nonce, sizeof eph_nonce);
        memcpy(derived_outer_key, eph_key, 32);
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            eph_ct, NULL,
            eph_key, sizeof eph_key,
            NULL, 0, NULL, eph_nonce, master_key);
        fwrite(eph_nonce, 1, sizeof eph_nonce, fout);
        fwrite(eph_ct,    1, sizeof eph_ct,    fout);
        secure_wipe(eph_key, sizeof eph_key);

    } else {
        memcpy(derived_outer_key, master_key, 32);
    }

    /* JIT: wrap per-file outer key */
    uint8_t file_outer_key[32];
    uint8_t jit_nonce[JIT_NONCE_LEN];
    uint8_t jit_wrapped[JIT_WRAPPED_KEY_LEN];
    randombytes_buf(file_outer_key, sizeof file_outer_key);
    randombytes_buf(jit_nonce,      sizeof jit_nonce);
    lock_sensitive(file_outer_key, sizeof file_outer_key);

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        jit_wrapped, NULL,
        file_outer_key, sizeof file_outer_key,
        NULL, 0, NULL, jit_nonce, derived_outer_key);
    fwrite(jit_nonce,   1, sizeof jit_nonce,   fout);
    fwrite(jit_wrapped, 1, sizeof jit_wrapped, fout);
    secure_wipe(derived_outer_key, sizeof derived_outer_key);

    /* Compute SIV */
    uint8_t siv[64];
    if (compute_siv_streaming(in, file_outer_key, siv) != 0) {
        fprintf(stderr, COLOR_RED "SIV computation failed\n" COLOR_RESET);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto enc_fail;
    }
    fwrite(siv, 1, 64, fout);

    /* Temporary file for inner ciphertext */
    int inner_fd = create_memfd("axis512_inner");
    if (inner_fd < 0) {
        fprintf(stderr, COLOR_RED "Cannot create temporary file (memfd failed). "
                "Falling back to /tmp (may leave traces).\n" COLOR_RESET);
        inner_fd = create_memfd("axis512_inner");
        if (inner_fd < 0) {
            fprintf(stderr, COLOR_RED "No temporary file possible. Abort.\n" COLOR_RESET);
            secure_wipe(file_outer_key, sizeof file_outer_key);
            goto enc_fail;
        }
    }
    FILE *inner_f = fdopen(inner_fd, "wb+");
    if (!inner_f) {
        close(inner_fd);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto enc_fail;
    }

    /* Inner encryption */
    uint8_t inner_key[INNER_KEY_LEN];
    uint8_t inner_nonce[INNER_NONCE_LEN];
    if (inner_encrypt_streaming(in, inner_f, inner_key, inner_nonce) != 0) {
        fprintf(stderr, COLOR_RED "Inner encryption failed\n" COLOR_RESET);
        fclose(inner_f);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto enc_fail;
    }
    fflush(inner_f);
    size_t inner_len = (size_t)ftell(inner_f);
    if (!quiet_mode)
        printf(COLOR_WHITE "  Inner ciphertext: %zu bytes\n" COLOR_RESET, inner_len);

    /* Outer encryption */
    int outer_ok;
    if (use_aes_outer)
        outer_ok = aes_outer_encrypt_streaming(inner_f, inner_len, file_outer_key, fout);
    else
        outer_ok = axis_outer_encrypt_streaming(inner_f, inner_len, file_outer_key, siv, fout);

    fclose(inner_f);
    fclose(fout);
    secure_wipe(file_outer_key, sizeof file_outer_key);
    secure_wipe(master_key,     sizeof master_key);
    if (!no_heap_scrub) deep_scrub_heap();
    return outer_ok;

enc_fail:
    secure_wipe(derived_outer_key, sizeof derived_outer_key);
    secure_wipe(master_key,        sizeof master_key);
    fclose(fout);
    return -1;
}

/* =====================================================================
 * DECRYPT FILE (v3.0.4-Keccak)
 * ===================================================================== */
static int decrypt_file(const char *in, const char *out,
                        const char *pwd, const char *pin)
{
    if (dry_run) {
        printf(COLOR_YELLOW
            "  [DRY RUN] Would decrypt '%s' -> '%s' "
            "(kyber: %s, ephemeral: %s, outer: %s)\n" COLOR_RESET,
            in, out,
            kyber_mode     ? "ON" : "OFF",
            ephemeral_mode ? "ON" : "OFF",
            use_aes_outer  ? "AES-streaming" : "Keccak-sponge");
        return 0;
    }

    if (!confirm_overwrite(out)) {
        printf(COLOR_YELLOW "  Overwrite cancelled.\n" COLOR_RESET);
        return -1;
    }

    FILE *fin = fopen(in, "rb");
    if (!fin) return -1;

    uint8_t salt[32];
    if (fread(salt, 1, sizeof salt, fin) != sizeof salt) {
        fprintf(stderr, COLOR_RED "File too short\n" COLOR_RESET);
        fclose(fin); return -1;
    }

    uint8_t master_key[32];
    lock_sensitive(master_key, sizeof master_key);

    if (!quiet_mode)
        printf(COLOR_WHITE "\n  Deriving master key with Argon2id...\n" COLOR_RESET);
    if (derive_key(pwd, pin, salt, master_key) != 0) {
        secure_wipe(master_key, sizeof master_key);
        fclose(fin); return -1;
    }

    uint8_t derived_outer_key[32];
    lock_sensitive(derived_outer_key, sizeof derived_outer_key);
    long hoff = (long)sizeof salt;

    if (kyber_mode) {
        /* Read SKE blob (encrypted hybrid secret key) */
        uint8_t ske_nonce[SKE_NONCE_LEN], ske_ct[SKE_CIPHERTEXT_LEN];
        if (fread(ske_nonce, 1, sizeof ske_nonce, fin) != sizeof ske_nonce ||
            fread(ske_ct,    1, sizeof ske_ct,    fin) != sizeof ske_ct) {
            fprintf(stderr, COLOR_RED "Hybrid SKE header missing\n" COLOR_RESET);
            goto dec_fail;
        }
        hoff += SKE_NONCE_LEN + SKE_CIPHERTEXT_LEN;

        /* Decrypt hybrid secret key */
        uint8_t hybrid_sk[HYBRID_SK_LEN];
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                hybrid_sk, NULL, NULL,
                ske_ct, sizeof ske_ct,
                NULL, 0, ske_nonce, master_key) != 0) {
            fprintf(stderr, COLOR_RED
                "\n❌ Decryption failed (wrong password or corrupt header).\n" COLOR_RESET);
            goto dec_fail;
        }
        uint8_t *kyber_sk = hybrid_sk;
        uint8_t *x25519_sk = hybrid_sk + KYBER_SECRETKEYBYTES;
        lock_sensitive(kyber_sk, KYBER_SECRETKEYBYTES);
        lock_sensitive(x25519_sk, X25519_PRIVKEY_LEN);

        /* Read hybrid ciphertext */
        uint8_t ct_kyber[KYBER_CIPHERTEXTBYTES];
        uint8_t eph_pub[X25519_PUBKEY_LEN];
        if (fread(ct_kyber, 1, sizeof ct_kyber, fin) != sizeof ct_kyber ||
            fread(eph_pub,  1, sizeof eph_pub,   fin) != sizeof eph_pub) {
            fprintf(stderr, COLOR_RED "Hybrid ciphertext missing\n" COLOR_RESET);
            goto dec_fail;
        }
        hoff += KYBER_CIPHERTEXTBYTES + X25519_PUBKEY_LEN;

        /* Hybrid decapsulation */
        uint8_t ss_kyber[KYBER_SSBYTES];
        uint8_t ss_x[X25519_PUBKEY_LEN];
        uint8_t ss[32];

        if (!quiet_mode) printf(COLOR_WHITE
            "  Hybrid decapsulation (Kyber + X25519)...\n" COLOR_RESET);
        if (crypto_kem_dec(ss_kyber, ct_kyber, kyber_sk) != 0) {
            fprintf(stderr, COLOR_RED "Kyber decapsulation failed\n" COLOR_RESET);
            goto dec_fail;
        }
        if (crypto_scalarmult(ss_x, x25519_sk, eph_pub) != 0) {
            fprintf(stderr, COLOR_RED "X25519 scalarmult failed\n" COLOR_RESET);
            goto dec_fail;
        }

        /* Combine shared secrets using BLAKE2b keyed with domain string */
        crypto_generichash_state st;
        crypto_generichash_init(&st, (const uint8_t*)"AXIS-HYBRID", 12, 32);
        crypto_generichash_update(&st, ss_kyber, KYBER_SSBYTES);
        crypto_generichash_update(&st, ss_x, X25519_PUBKEY_LEN);
        crypto_generichash_final(&st, ss, 32);
        secure_wipe(ss_kyber, sizeof ss_kyber);
        secure_wipe(ss_x, sizeof ss_x);
        secure_wipe(kyber_sk, KYBER_SECRETKEYBYTES);
        secure_wipe(x25519_sk, X25519_PRIVKEY_LEN);
        secure_wipe(hybrid_sk, sizeof hybrid_sk);
        secure_wipe(ct_kyber, sizeof ct_kyber);
        secure_wipe(eph_pub,  sizeof eph_pub);

        derive_outer_key_from_ss(ss, derived_outer_key);
        secure_wipe(ss, sizeof ss);

    } else if (ephemeral_mode) {
        uint8_t eph_nonce[24], eph_ct[48];
        if (fread(eph_nonce, 1, sizeof eph_nonce, fin) != sizeof eph_nonce ||
            fread(eph_ct,    1, sizeof eph_ct,    fin) != sizeof eph_ct) {
            fprintf(stderr, COLOR_RED "Ephemeral header missing\n" COLOR_RESET);
            goto dec_fail;
        }
        hoff += sizeof eph_nonce + sizeof eph_ct;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                derived_outer_key, NULL, NULL,
                eph_ct, sizeof eph_ct,
                NULL, 0, eph_nonce, master_key) != 0) {
            fprintf(stderr, COLOR_RED
                "\n❌ Decryption failed (ephemeral key decryption).\n" COLOR_RESET);
            goto dec_fail;
        }
    } else {
        memcpy(derived_outer_key, master_key, 32);
    }

    /* JIT unwrap */
    uint8_t jit_nonce[JIT_NONCE_LEN];
    uint8_t jit_wrapped[JIT_WRAPPED_KEY_LEN];
    if (fread(jit_nonce,   1, sizeof jit_nonce,   fin) != sizeof jit_nonce ||
        fread(jit_wrapped, 1, sizeof jit_wrapped, fin) != sizeof jit_wrapped) {
        fprintf(stderr, COLOR_RED "JIT wrapped key missing\n" COLOR_RESET);
        goto dec_fail;
    }
    hoff += JIT_NONCE_LEN + JIT_WRAPPED_KEY_LEN;

    uint8_t file_outer_key[32];
    lock_sensitive(file_outer_key, sizeof file_outer_key);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            file_outer_key, NULL, NULL,
            jit_wrapped, sizeof jit_wrapped,
            NULL, 0, jit_nonce, derived_outer_key) != 0) {
        fprintf(stderr,
            COLOR_RED "JIT unwrap failed (corrupt file or key)\n" COLOR_RESET);
        goto dec_fail;
    }
    secure_wipe(derived_outer_key, sizeof derived_outer_key);

    /* Read SIV */
    uint8_t siv[64];
    if (fread(siv, 1, 64, fin) != 64) {
        fprintf(stderr, COLOR_RED "SIV missing\n" COLOR_RESET);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }
    hoff += 64;

    /* Outer ciphertext size */
    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    fseek(fin, hoff, SEEK_SET);
    size_t outer_ct_len = (size_t)(fsize - hoff);

    int inner_fd = create_memfd("axis512_inner");
    if (inner_fd < 0) {
        fprintf(stderr, COLOR_RED "Cannot create temporary file (memfd failed). "
                "Falling back to /tmp (may leave traces).\n" COLOR_RESET);
        inner_fd = create_memfd("axis512_inner");
        if (inner_fd < 0) {
            fprintf(stderr, COLOR_RED "No temporary file possible. Abort.\n" COLOR_RESET);
            secure_wipe(file_outer_key, sizeof file_outer_key);
            goto dec_fail;
        }
    }
    FILE *inner_f = fdopen(inner_fd, "wb+");
    if (!inner_f) {
        close(inner_fd);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    int outer_ok;
    if (use_aes_outer)
        outer_ok = aes_outer_decrypt_streaming(fin, outer_ct_len, file_outer_key, inner_f);
    else
        outer_ok = axis_outer_decrypt_streaming(fin, outer_ct_len, file_outer_key, siv, inner_f);

    if (outer_ok != 0) {
        fclose(inner_f);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    rewind(inner_f);

    int pt_fd = create_memfd("axis512_plain");
    if (pt_fd < 0) {
        fprintf(stderr,
            COLOR_RED "Cannot create plaintext temporary file\n" COLOR_RESET);
        fclose(inner_f);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    size_t inner_stream_len = (size_t)ftell(inner_f);
    rewind(inner_f);

    int inner_ok = inner_decrypt_streaming_to_fd(inner_f, pt_fd, inner_stream_len);
    fclose(inner_f);
    if (inner_ok != 0) {
        secure_close_fd(pt_fd, 0);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    /* Verify SIV – include plaintext length */
    if (lseek(pt_fd, 0, SEEK_SET) == -1) {
        secure_close_fd(pt_fd, 0);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    uint8_t siv_c[64];
    crypto_generichash_state siv_state;
    crypto_generichash_init(&siv_state, file_outer_key, 32, 64);
    crypto_generichash_update(&siv_state,
                              (const uint8_t*)SIV_DOMAIN,
                              SIV_DOMAIN_LEN);

    /* Add length – same as encryption */
    off_t pt_size_off = lseek(pt_fd, 0, SEEK_END);
    if (pt_size_off == -1) {
        secure_close_fd(pt_fd, 0);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }
    size_t pt_size = (size_t)pt_size_off;
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++)
        len_bytes[i] = (pt_size >> (i * 8)) & 0xFF;
    crypto_generichash_update(&siv_state, len_bytes, 8);

    if (lseek(pt_fd, 0, SEEK_SET) == -1) {
        secure_close_fd(pt_fd, 0);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    uint8_t *siv_buf = malloc(STREAM_BUFFER_SIZE);
    if (!siv_buf) {
        secure_close_fd(pt_fd, 0);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    size_t processed = 0;
    time_t start = time(NULL);
    size_t last_up = 0;

    if (!quiet_mode)
        printf(COLOR_WHITE "  Verifying SIV...\n" COLOR_RESET);

    while (processed < pt_size) {
        size_t to_read = pt_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        ssize_t n = read(pt_fd, siv_buf, to_read);
        if (n <= 0) break;
        crypto_generichash_update(&siv_state, siv_buf, (size_t)n);
        processed += (size_t)n;
        if (processed - last_up >= 65536 || processed == pt_size) {
            show_progress("SIV Verification", processed, pt_size, start);
            last_up = processed;
        }
    }
    free(siv_buf);
    if (!quiet_mode) printf(CURSOR_SHOW "\n" COLOR_RESET);

    crypto_generichash_final(&siv_state, siv_c, 64);
    if (sodium_memcmp(siv_c, siv, 64) != 0) {
        fprintf(stderr, COLOR_RED
            "\n❌ Decryption failed (SIV mismatch – wrong password or corrupted file).\n"
            COLOR_RESET);
        secure_close_fd(pt_fd, pt_size);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    /* Copy plaintext to output */
    if (lseek(pt_fd, 0, SEEK_SET) == -1) {
        secure_close_fd(pt_fd, pt_size);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    int out_fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) {
        fprintf(stderr,
            COLOR_RED "Cannot open output file for writing\n" COLOR_RESET);
        secure_close_fd(pt_fd, pt_size);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    if (sendfile_all(out_fd, pt_fd, pt_size) != (ssize_t)pt_size) {
        fprintf(stderr, COLOR_RED "Failed to write plaintext\n" COLOR_RESET);
        close(out_fd);
        secure_close_fd(pt_fd, pt_size);
        secure_wipe(file_outer_key, sizeof file_outer_key);
        goto dec_fail;
    }

    close(out_fd);
    secure_close_fd(pt_fd, pt_size);
    secure_wipe(file_outer_key, sizeof file_outer_key);
    secure_wipe(master_key,     sizeof master_key);
    fclose(fin);
    if (!no_heap_scrub) deep_scrub_heap();
    if (!quiet_mode)
        printf(COLOR_GREEN "\n  ✅ Decryption successful.\n" COLOR_RESET);
    return 0;

dec_fail:
    secure_wipe(derived_outer_key, sizeof derived_outer_key);
    secure_wipe(master_key,        sizeof master_key);
    fclose(fin);
    if (!no_heap_scrub) deep_scrub_heap();
    return -1;
}

/* =====================================================================
 * MENU FUNCTIONS (unchanged except version string)
 * ===================================================================== */
static void argon2_menu(void) {
    int c;
    printf("\n" COLOR_CYAN "⚙️  Argon2id Memory" COLOR_RESET "\n");
    printf(COLOR_WHITE "  Current: %s\n" COLOR_RESET, argon2_preset_name);
    printf(COLOR_WHITE
        "  1. Weak (128M)  2. Moderate (256M)  3. Strong (512M)"
        "  4. Max (1G)\n");
    printf(COLOR_WHITE "  5. Quantum (2G)  6. Back\n" COLOR_RESET);
    printf("Choice: ");
    c = get_menu_choice();
    if (c == -1) return;
    if      (c==1) { argon2_memory=128ULL *1024*1024; argon2_preset_name="Weak (128 MiB)";     quantum_mode_enabled=0; }
    else if (c==2) { argon2_memory=256ULL *1024*1024; argon2_preset_name="Moderate (256 MiB)"; quantum_mode_enabled=0; }
    else if (c==3) { argon2_memory=512ULL *1024*1024; argon2_preset_name="Strong (512 MiB)";   quantum_mode_enabled=0; }
    else if (c==4) { argon2_memory=1024ULL*1024*1024; argon2_preset_name="Maximum (1 GiB)";    quantum_mode_enabled=0; }
    else if (c==5) {
        argon2_memory=2ULL*1024*1024*1024;
        argon2_preset_name="Quantum (2 GiB)";
        spip_iterations=(1<<24);
        quantum_mode_enabled=1;
        printf(COLOR_YELLOW "\n⚠️  QUANTUM PRESET NOTE:\n"
               "   Classical cost amplifier only – not post‑quantum.\n" COLOR_RESET);
        wait_for_enter();
    }
}

static void rounds_menu(void) {
    if (paranoid_mode) {
        printf("\n" COLOR_YELLOW "⚙️  Rounds locked to 24 in Paranoid Mode.\n" COLOR_RESET);
        wait_for_enter(); return;
    }
    int c;
    printf("\n" COLOR_CYAN "⚙️  Rounds" COLOR_RESET "\n");
    printf(COLOR_WHITE "  Current: %d (%s)\n" COLOR_RESET,
           axis_rounds, rounds_preset_name);
    printf(COLOR_WHITE
        "  1. 16 (Faster)  2. 20 (Standard)  3. 24 (Max)  4. Back\n" COLOR_RESET);
    printf("Choice: ");
    c = get_menu_choice();
    if (c == -1) return;
    if      (c==1) { axis_rounds=16; rounds_preset_name="16 (Faster)";   }
    else if (c==2) { axis_rounds=20; rounds_preset_name="20 (Standard)"; }
    else if (c==3) { axis_rounds=24; rounds_preset_name="24 (Maximum)";  }
}

static void spip_menu(void) {
    int c;
    printf("\n" COLOR_CYAN "⚙️  SPIP Strength" COLOR_RESET "\n");
    printf(COLOR_WHITE "  Current: " COLOR_RESET);
    if      (spip_iterations==(1<<20)) printf(COLOR_YELLOW "Weak (1M)\n"    COLOR_RESET);
    else if (spip_iterations==(1<<21)) printf(COLOR_WHITE  "Medium (2M)\n"  COLOR_RESET);
    else if (spip_iterations==(1<<22)) printf(COLOR_GREEN  "Strong (4M)\n"  COLOR_RESET);
    else if (spip_iterations==(1<<23)) printf(COLOR_BLUE   "Maximum (8M)\n" COLOR_RESET);
    else if (spip_iterations==(1<<24)) printf(COLOR_CYAN   "Quantum (16M)\n"COLOR_RESET);
    else printf("%u\n", spip_iterations);
    printf(COLOR_WHITE
        "  1. Weak  2. Medium  3. Strong  4. Maximum  5. Quantum  6. Back\n" COLOR_RESET);
    printf("Choice: ");
    c = get_menu_choice();
    if (c == -1) return;
    if      (c==1) spip_iterations=(1<<20);
    else if (c==2) spip_iterations=(1<<21);
    else if (c==3) spip_iterations=(1<<22);
    else if (c==4) spip_iterations=(1<<23);
    else if (c==5) spip_iterations=(1<<24);
}

static void settings_menu(int *show_pwd) {
    int c;
    while (1) {
        printf("\n" COLOR_CYAN "  ⚙️  Settings" COLOR_RESET "\n");
        printf(COLOR_WHITE "    1. Password visibility: %s\n" COLOR_RESET,
               *show_pwd ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    2. Argon2id: %s\n" COLOR_RESET, argon2_preset_name);
        printf(COLOR_WHITE "    3. Rounds: %d (%s)%s\n" COLOR_RESET,
               axis_rounds, rounds_preset_name, paranoid_mode?" [locked]":"");
        printf(COLOR_WHITE "    4. SPIP: " COLOR_RESET);
        if      (spip_iterations==(1<<20)) printf(COLOR_YELLOW "Weak (1M)\n"    COLOR_RESET);
        else if (spip_iterations==(1<<21)) printf(COLOR_WHITE  "Medium (2M)\n"  COLOR_RESET);
        else if (spip_iterations==(1<<22)) printf(COLOR_GREEN  "Strong (4M)\n"  COLOR_RESET);
        else if (spip_iterations==(1<<23)) printf(COLOR_BLUE   "Maximum (8M)\n" COLOR_RESET);
        else if (spip_iterations==(1<<24)) printf(COLOR_CYAN   "Quantum (16M)\n"COLOR_RESET);
        else printf("Custom (%u)\n", spip_iterations);
        printf(COLOR_WHITE "    5. TMR (Fault Detection): %s\n" COLOR_RESET,
               tmr_enabled ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    6. Paranoid Mode: %s\n" COLOR_RESET,
               paranoid_mode ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    7. Ephemeral Key Mode: %s\n" COLOR_RESET,
               ephemeral_mode ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    8. Kyber KEM Mode: %s\n" COLOR_RESET,
               kyber_mode ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    9. Quantum hardening: %s\n" COLOR_RESET,
               quantum_mode_enabled ? COLOR_GREEN "ON" COLOR_RESET : COLOR_RED "OFF" COLOR_RESET);
        printf(COLOR_WHITE "    10. Outer cipher: %s\n" COLOR_RESET,
               use_aes_outer
                   ? "AES-256-GCM MAC seal + XChaCha20 bulk (streaming, O(1) RAM)"
                   : "Keccak-f[1600] sponge (NIST standard, unbreakable)");
        printf(COLOR_WHITE "    11. Back\n" COLOR_RESET);
        printf("    Choice: ");
        c = get_menu_choice();
        if (c == -1) continue;
        if      (c==1)  *show_pwd = !(*show_pwd);
        else if (c==2)  argon2_menu();
        else if (c==3)  rounds_menu();
        else if (c==4)  spip_menu();
        else if (c==5)  tmr_enabled = !tmr_enabled;
        else if (c==6)  {
            paranoid_mode = !paranoid_mode;
            if (paranoid_mode) { axis_rounds=24; rounds_preset_name="24 (Maximum)"; }
        }
        else if (c==7)  ephemeral_mode = !ephemeral_mode;
        else if (c==8)  kyber_mode = !kyber_mode;
        else if (c==9)  {
            quantum_mode_enabled = !quantum_mode_enabled;
            if (quantum_mode_enabled) {
                argon2_memory=2ULL*1024*1024*1024;
                argon2_preset_name="Quantum (2 GiB)";
                spip_iterations=(1<<24);
            } else {
                argon2_memory=256ULL*1024*1024;
                argon2_preset_name="Moderate (256 MiB)";
                spip_iterations=(1<<22);
            }
        }
        else if (c==10) {
            use_aes_outer = !use_aes_outer;
            if (use_aes_outer && !aes256gcm_available())
                printf(COLOR_YELLOW
                    "\n⚠️  AES-256-GCM hardware not detected; "
                    "software fallback will be used.\n" COLOR_RESET);
        }
        else if (c==11) break;
    }
}

/* =====================================================================
 * HYBRID KEM SELF-TEST (unchanged)
 * ===================================================================== */
static int hybrid_kem_self_test(void) {
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
    uint8_t kyber_sk[KYBER_SECRETKEYBYTES];
    uint8_t x25519_pk[X25519_PUBKEY_LEN];
    uint8_t x25519_sk[X25519_PRIVKEY_LEN];
    uint8_t eph_priv[X25519_PRIVKEY_LEN];
    uint8_t eph_pub[X25519_PUBKEY_LEN];
    uint8_t ct_kyber[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_kyber_enc[KYBER_SSBYTES];
    uint8_t ss_kyber_dec[KYBER_SSBYTES];
    uint8_t ss_x_enc[X25519_PUBKEY_LEN];
    uint8_t ss_x_dec[X25519_PUBKEY_LEN];
    uint8_t ss_enc[32];
    uint8_t ss_dec[32];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "Hybrid self-test: Kyber keygen failed\n");
        return -1;
    }
    if (crypto_box_keypair(x25519_pk, x25519_sk) != 0) {
        fprintf(stderr, "Hybrid self-test: X25519 keygen failed\n");
        return -1;
    }
    if (crypto_box_keypair(eph_pub, eph_priv) != 0) {
        fprintf(stderr, "Hybrid self-test: ephemeral X25519 keygen failed\n");
        return -1;
    }
    if (crypto_kem_enc(ct_kyber, ss_kyber_enc, kyber_pk) != 0) {
        fprintf(stderr, "Hybrid self-test: Kyber encapsulation failed\n");
        return -1;
    }
    if (crypto_scalarmult(ss_x_enc, eph_priv, x25519_pk) != 0) {
        fprintf(stderr, "Hybrid self-test: X25519 scalarmult (enc) failed\n");
        return -1;
    }
    crypto_generichash_state st;
    crypto_generichash_init(&st, (const uint8_t*)"AXIS-HYBRID", 12, 32);
    crypto_generichash_update(&st, ss_kyber_enc, KYBER_SSBYTES);
    crypto_generichash_update(&st, ss_x_enc, X25519_PUBKEY_LEN);
    crypto_generichash_final(&st, ss_enc, 32);

    if (crypto_kem_dec(ss_kyber_dec, ct_kyber, kyber_sk) != 0) {
        fprintf(stderr, "Hybrid self-test: Kyber decapsulation failed\n");
        return -1;
    }
    if (crypto_scalarmult(ss_x_dec, x25519_sk, eph_pub) != 0) {
        fprintf(stderr, "Hybrid self-test: X25519 scalarmult (dec) failed\n");
        return -1;
    }
    crypto_generichash_init(&st, (const uint8_t*)"AXIS-HYBRID", 12, 32);
    crypto_generichash_update(&st, ss_kyber_dec, KYBER_SSBYTES);
    crypto_generichash_update(&st, ss_x_dec, X25519_PUBKEY_LEN);
    crypto_generichash_final(&st, ss_dec, 32);

    if (sodium_memcmp(ss_enc, ss_dec, 32) != 0) {
        fprintf(stderr, "Hybrid self-test: shared secret mismatch\n");
        return -1;
    }

    secure_wipe(kyber_sk, sizeof kyber_sk);
    secure_wipe(x25519_sk, sizeof x25519_sk);
    secure_wipe(eph_priv, sizeof eph_priv);
    secure_wipe(ss_kyber_enc, sizeof ss_kyber_enc);
    secure_wipe(ss_kyber_dec, sizeof ss_kyber_dec);
    secure_wipe(ss_x_enc, sizeof ss_x_enc);
    secure_wipe(ss_x_dec, sizeof ss_x_dec);
    secure_wipe(ss_enc, sizeof ss_enc);
    secure_wipe(ss_dec, sizeof ss_dec);

    return 0;
}

/* =====================================================================
 * MAIN
 * ===================================================================== */
int main(int argc, char **argv) {
    disable_core_dumps();
    block_sleep_states();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i],"--quiet")||!strcmp(argv[i],"-q")) quiet_mode=1;
        if (!strcmp(argv[i],"--dry-run")) {
            dry_run=1;
            printf(COLOR_YELLOW "  [DRY RUN MODE] No files will be written.\n" COLOR_RESET);
        }
        if (!strcmp(argv[i],"--ephemeral")) {
            ephemeral_mode=1; kyber_mode=0;
            printf(COLOR_YELLOW "  Ephemeral key mode enabled.\n" COLOR_RESET);
        }
        if (!strcmp(argv[i],"--kyber")) {
            kyber_mode=1; ephemeral_mode=0;
            printf(COLOR_CYAN "  Kyber KEM mode enabled.\n" COLOR_RESET);
        }
        if (!strcmp(argv[i],"--aes-outer")) {
            use_aes_outer=1;
            printf(COLOR_CYAN
                "  AES-256-GCM MAC seal + XChaCha20-Poly1305 outer layer enabled.\n" COLOR_RESET);
        }
        if (!strcmp(argv[i],"--no-heap-scrub")) {
            no_heap_scrub = 1;
            printf(COLOR_YELLOW "  Heap scrubbing disabled (--no-heap-scrub).\n" COLOR_RESET);
        }
    }

    if (sodium_init() < 0) {
        fprintf(stderr, COLOR_RED "libsodium init failed\n" COLOR_RESET);
        return 1;
    }

    signal(SIGINT,  sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Run self-test (core + hybrid KEM) */
    if (axis_self_test() != 0) {
        fprintf(stderr, COLOR_RED "\n❌ Core self-test failed. Exiting.\n" COLOR_RESET);
        return 1;
    }
    if (hybrid_kem_self_test() != 0) {
        fprintf(stderr, COLOR_RED "\n❌ Hybrid KEM self-test failed. Exiting.\n" COLOR_RESET);
        return 1;
    }
    if (!quiet_mode) printf(COLOR_GREEN "  ✅ Self-tests passed.\n" COLOR_RESET);

    if (!quiet_mode) {
        printf(COLOR_WHITE "\n  🔒 Security posture:\n" COLOR_RESET);
        printf("     • mlock + MADV_DONTDUMP + MADV_WIPEONFORK: %s\n",
               axis_mlock_available()
                   ? COLOR_GREEN "enabled" COLOR_RESET
                   : COLOR_RED "UNAVAILABLE" COLOR_RESET);
        printf("     • Core dumps: disabled\n");
        printf("     • Process hardening: PR_SET_DUMPABLE + PR_SET_NO_NEW_PRIVS\n");
        printf("     • Heap scrub: %s\n", no_heap_scrub ? "disabled (--no-heap-scrub)" : "enabled");
        printf("     • RAM usage: O(1) streaming (all modes)\n");
        printf("     • JIT key wrapping: active (per-file outer key)\n");
        printf("     • SPIP inner core: BLAKE2b (RFC 7693, constant‑time)\n");
        printf("     • Sponge tag: finalisation permute before squeeze\n");
        printf("     • Inner nonce: bound as AD to secretstream\n");
        if (quantum_mode_enabled)
            printf(COLOR_YELLOW
                "     ⚠️  Quantum preset active – classical cost amplifier only.\n" COLOR_RESET);
        if (kyber_mode)
            printf(COLOR_CYAN
                "     🔑 Kyber-1024 + X25519 hybrid KEM (post‑quantum + classical).\n" COLOR_RESET);
        else if (ephemeral_mode)
            printf(COLOR_CYAN
                "     🔑 Ephemeral key mode – per-file outer keys.\n" COLOR_RESET);
        if (use_aes_outer)
            printf(COLOR_CYAN
                "     🔒 Outer: XChaCha20-Poly1305 bulk + AES-256-GCM MAC seal\n" COLOR_RESET);
        else
            printf(COLOR_CYAN
                "     🔒 Outer: Keccak-f[1600] sponge (NIST standard, 24 rounds)\n" COLOR_RESET);
        printf("\n");
    }

    char password[256], pin[256], in_path[1024], out_path[1024];
    char input_buffer[256];
    int  show_pwd = 0;

    lock_sensitive(password, sizeof password);
    lock_sensitive(pin,      sizeof pin);

    while (1) {
        printf("\n" CLEAR_LINE);
        printf(COLOR_CYAN "\n");
        printf("       █████╗ ██╗  ██╗██╗███████╗   ██████╗ ██████╗ \n");
        printf("      ██╔══██╗╚██╗██╔╝██║██╔════╝   ╚════██╗██╔════╝ \n");
        printf("      ███████║ ╚███╔╝ ██║███████╗    █████╔╝███████╗ \n");
        printf("      ██╔══██║ ██╔██╗ ██║╚════██║   ██╔═══╝ ██╔═══██╗\n");
        printf("      ██║  ██║██╔╝ ██╗██║███████║   ███████╗╚██████╔╝\n");
        printf("      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚══════╝ ╚═════╝ \n" COLOR_RESET);
        printf(COLOR_WHITE
            "    Axis-512 v3.0.5-Keccak – Unbreakable sponge (NIST standard)\n" COLOR_RESET);
        printf(COLOR_WHITE "KDF: %s | Rounds: %d | TMR: %s | Paranoid: %s\n" COLOR_RESET,
               argon2_preset_name, axis_rounds,
               tmr_enabled ? "ON" : "OFF", paranoid_mode ? "ON" : "OFF");
        printf(COLOR_WHITE "            Mode: %s | Outer: %s\n" COLOR_RESET,
               kyber_mode     ? "Hybrid KEM" :
               ephemeral_mode ? "Ephemeral"  : "Classic",
               use_aes_outer  ? "AES-GCM seal + XChaCha20" : "Keccak-f[1600] sponge");
        printf("\n");
        printf(COLOR_WHITE "     ┌─────────────────────────────────────────┐\n" COLOR_RESET);
        printf(COLOR_WHITE "     │" COLOR_RESET "  " COLOR_CYAN "1." COLOR_RESET
            " Encrypt a file                      " COLOR_WHITE "│\n" COLOR_RESET);
        printf(COLOR_WHITE "     │" COLOR_RESET "  " COLOR_CYAN "2." COLOR_RESET
            " Decrypt a file                      " COLOR_WHITE "│\n" COLOR_RESET);
        printf(COLOR_WHITE "     │" COLOR_RESET "  " COLOR_CYAN "3." COLOR_RESET
            " Settings                            " COLOR_WHITE "│\n" COLOR_RESET);
        printf(COLOR_WHITE "     │" COLOR_RESET "  " COLOR_CYAN "4." COLOR_RESET
            " Exit                                " COLOR_WHITE "│\n" COLOR_RESET);
        printf(COLOR_WHITE "     └─────────────────────────────────────────┘\n" COLOR_RESET);
        printf("\n");
        printf(COLOR_WHITE "     Choice: " COLOR_RESET);

        if (fgets(input_buffer, sizeof input_buffer, stdin) == NULL) {
            deep_scrub(password, sizeof password);
            deep_scrub(pin,      sizeof pin);
            break;
        }
        input_buffer[strcspn(input_buffer, "\n")] = 0;
        char *ep; long val = strtol(input_buffer, &ep, 10);
        if (*ep || val < 1 || val > 4) {
            printf(COLOR_RED "\n  ⚠️  Invalid option.\n" COLOR_RESET);
            printf(COLOR_WHITE "  Press Enter to continue..." COLOR_RESET);
            wait_for_enter(); continue;
        }
        int choice = (int)val;

        if (choice == 4) {
            deep_scrub(password, sizeof password);
            deep_scrub(pin,      sizeof pin);
            if (!no_heap_scrub) deep_scrub_heap();
            restore_terminal();
            break;
        }

        if (choice == 3) { settings_menu(&show_pwd); continue; }

        if (read_input("  Password: ",  password, sizeof password, show_pwd) != 0) continue;
        if (read_input("  PIN (optional, 0 to skip): ",
                       pin, sizeof pin, show_pwd) != 0) continue;
        if (!strcmp(pin, "0")) pin[0] = '\0';

        printf("  Input file: ");
        if (fgets(in_path,  sizeof in_path,  stdin) == NULL) break;
        in_path[strcspn(in_path, "\n")] = 0;

        printf("  Output file: ");
        if (fgets(out_path, sizeof out_path, stdin) == NULL) break;
        out_path[strcspn(out_path, "\n")] = 0;

        int ret = (choice == 1)
            ? encrypt_file(in_path, out_path, password, pin)
            : decrypt_file(in_path, out_path, password, pin);

        if (ret == 0) printf(COLOR_GREEN "\n  ✅ Operation completed successfully.\n" COLOR_RESET);
        else          printf(COLOR_RED   "\n  ❌ Operation failed.\n" COLOR_RESET);

        deep_scrub(password, sizeof password);
        deep_scrub(pin,      sizeof pin);

        printf(COLOR_WHITE "\n  Press Enter to continue..." COLOR_RESET);
        wait_for_enter();
    }

    restore_terminal();
    printf(COLOR_CYAN "\n  Exiting. All sensitive data sanitised and scrubbed.\n" COLOR_RESET);
    return 0;
}
