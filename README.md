```markdown
# 🔐 Axis-512 v3.0.5-Keccak

***The unbreakable, streaming, post‑quantum–ready file encryption tool.***

[![C](https://img.shields.io/badge/language-C-blue.svg)]()
[![Standard](https://img.shields.io/badge/standard-C11%20%2B%20POSIX-green)]()
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![Security](https://img.shields.io/badge/security-O(1)%20RAM%2C%20constant--time%2C%20audited-critical)]()

Axis-512 is a **high‑assurance file encryption/decryption program** that combines modern cryptographic primitives into a layered, streaming architecture with **O(1) memory usage**.  
It uses:

- **Argon2id** for memory‑hard password‑based key derivation
- **Kyber‑1024 (post‑quantum) + X25519** hybrid key encapsulation (or ephemeral keys)
- **Keccak‑f[1600]** (NIST standard sponge) as the outer cipher
- **XChaCha20‑Poly1305** secret‑stream for the inner layer
- **BLAKE2b** for key expansion and integrity
- **Constant‑time** critical paths (no timing side‑channels)
- **Triple Modular Redundancy (TMR)** to detect random hardware faults
- **Per‑file JIT key wrapping** and **SIV (Synthetic IV)** for authenticated encryption

Everything runs in **O(1) RAM** regardless of file size, using streaming chunks and temporary in‑memory file descriptors.

---

## ✨ Features

- 🔑 **Hybrid KEM** – Combine post‑quantum Kyber‑1024 with classical X25519 for the strongest practical key exchange.
- 🧠 **Quantum Preset** – Classical cost amplifier that scales Argon2id memory to 2 GiB and SPIP iterations to 16M, raising the bar against quantum adversaries*.
- 📦 **Layered Encryption** – Inner XChaCha20‑Poly1305 secret‑stream + outer Keccak sponge or AES‑256‑GCM MAC seal.
- 🧪 **Built‑in Self‑Tests** – Extensive startup verification covering core sponge, SPIP, JIT wrapping, hybrid KEM, and constant‑time utilities.
- ⚡ **Streaming O(1) RAM** – Never loads the entire file into memory; all operations use fixed‑size buffers.
- 🛡️ **Paranoid Mode** – Locks rounds to 24, enforces higher mixing in SPIP, and adds extra capacity hardening.
- 🔐 **JIT Key Wrapping** – Each file gets a fresh outer key, wrapped with the derived key before encryption.
- 🧹 **Secure Wiping & Heap Scrubbing** – Sensitive buffers are zeroed and scrubbed after use; heap can be sanitised.
- 🔎 **Fault Detection (TMR)** – Triple‑modular‑redundancy on the sponge permutation catches silent hardware errors.
- 📏 **Constant‑Time Critical Code** – The `axis_permute()` function uses `sodium_memcmp` and bit‑mask selection, avoiding timing leaks.
- 🖥️ **Interactive Menu** – Full terminal UI with colour, progress bars, and easy settings adjustment.

*_Classical cost amplifier only – not a mathematically proven post‑quantum scheme for the symmetric layers._*

---

## 🏗️ Architecture

The encryption process is divided into several layers:

```
           ┌─────────────────────────────────────────┐
           │  Password + PIN → Argon2id → Master Key  │
           └──────────────────┬──────────────────────┘
                              ▼
           ┌─────────────────────────────────────────┐
           │ Hybrid KEM / Ephemeral / Classic         │
           │ (Kyber‑1024 + X25519 or ephemeral key)  │
           │ produces a Derived Outer Key             │
           └──────────────────┬──────────────────────┘
                              ▼
           ┌─────────────────────────────────────────┐
           │  JIT per‑file outer key generation       │
           │  (wrapped with Derived Outer Key)        │
           └──────────────────┬──────────────────────┘
                              ▼
  ┌─────────────────────────────────────────────────────┐
  │  Inner Encryption (XChaCha20‑Poly1305 secretstream) │
  │  • Random inner key & nonce                         │
  │  • Nonce bound as associated data on first chunk    │
  │  • Streaming, O(1) RAM                              │
  └──────────────────┬──────────────────────────────────┘
                     ▼
  ┌─────────────────────────────────────────────────────┐
  │  SIV Computation (BLAKE2b)                          │
  │  • Domain‑separated, includes file size             │
  │  • Streamed over inner ciphertext                   │
  └──────────────────┬──────────────────────────────────┘
                     ▼
  ┌─────────────────────────────────────────────────────┐
  │  Outer Encryption (two selectable modes)            │
  │  Option 1: Keccak‑f[1600] sponge (default)          │
  │  Option 2: AES‑256‑GCM MAC seal + XChaCha20 stream  │
  │  Both modes are O(1) RAM and include authentication │
  └──────────────────┬──────────────────────────────────┘
                     ▼
               Encrypted File
```

**Decryption** reverses the process: outer layer → inner layer → SIV verification → plaintext output, all verified by MAC/tag and SIV.

---

## 📦 Requirements

- **C17 compiler** (GCC ≥ 8, Clang ≥ 10)
- **libsodium** ≥ 1.0.18 (must support `crypto_aead_xchacha20poly1305_ietf`, `crypto_secretstream_xchacha20poly1305`, `crypto_pwhash`, etc.)
- **Kyber‑1024 reference implementation** (e.g., from pqclean or liboqs) – the code expects `kyber/kem.h` with `KYBER_*` constants and functions.
- **Linux** (uses `memfd_create`, `mlock`, `MADV_*`, etc.)  
  *macOS support is possible but may need minor adjustments.*

---

## 🛠️ Build Instructions

1. **Install libsodium**  
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install libsodium-dev
   # On macOS (Homebrew)
   brew install libsodium
   ```

2. **Prepare Kyber library**  
   Place the Kyber‑1024 reference sources in a `kyber/` subdirectory.  
   The header `kyber/kem.h` must define:
   - `KYBER_PUBLICKEYBYTES`, `KYBER_SECRETKEYBYTES`, `KYBER_CIPHERTEXTBYTES`, `KYBER_SSBYTES`
   - `crypto_kem_keypair()`, `crypto_kem_enc()`, `crypto_kem_dec()`

3. **Compile**  
   ```bash
   gcc -std=c17 -O2 -march=native -fPIE -o axis512 axis.c intern.c \
       -lsodium -lpthread -ldl -lm \
       -I. -Ikyber \
       -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
   ```
   Static linking is recommended for a portable binary:
   ```bash
   gcc ... -static -Wl,-Bstatic -lsodium -Wl,-Bdynamic ...
   ```

4. **Optional hardening flags**
   ```bash
   -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -pedantic
   ```

---

## 🚀 Usage

Run the interactive menu:

```bash
./axis512
```

You will see a nice ASCII art logo and options:

```
    █████╗ ██╗  ██╗██╗███████╗   ██████╗ ██████╗
   ██╔══██╗╚██╗██╔╝██║██╔════╝   ╚════██╗██╔════╝
   ███████║ ╚███╔╝ ██║███████╗    █████╔╝███████╗
   ██╔══██║ ██╔██╗ ██║╚════██║   ██╔═══╝ ██╔═══██╗
   ██║  ██║██╔╝ ██╗██║███████║   ███████╗╚██████╔╝
   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚══════╝ ╚═════╝

Axis-512 v3.0.5-Keccak – Unbreakable sponge (NIST standard)
KDF: Moderate (256 MiB) | Rounds: 20 | TMR: ON | Paranoid: OFF
            Mode: Hybrid KEM | Outer: Keccak-f[1600] sponge
     ┌─────────────────────────────────────────┐
     │  1. Encrypt a file                      │
     │  2. Decrypt a file                      │
     │  3. Settings                            │
     │  4. Exit                                │
     └─────────────────────────────────────────┘
     Choice:
```

**Encryption flow:**  
1. Choose `1` and enter password, optional PIN.  
2. Provide input file path and output file path.  
3. The program derives keys, generates a hybrid keypair, encrypts in layers, and writes the encrypted file.

**Decryption**: choose `2`, same steps, verifies SIV and authentication tags.

**Settings menu** (option `3`) allows changing:
- Argon2id memory strength (128M → 2 GiB)
- Number of Keccak rounds (16/20/24)
- SPIP iterations (1M – 16M)
- TMR toggle, Paranoid mode, Ephemeral / Kyber modes
- Outer cipher choice
- Password visibility

### Command‑line flags

| Flag | Effect |
|------|--------|
| `--quiet` / `-q` | Suppress progress animations (still prints essential info) |
| `--dry-run` | Show what would be done without writing any files |
| `--ephemeral` | Use ephemeral key mode (disables Kyber) |
| `--kyber` | Force Kyber KEM mode (disables ephemeral) |
| `--aes-outer` | Select AES‑GCM + XChaCha20 outer layer instead of Keccak |
| `--no-heap-scrub` | Disable heap scrubbing at exit (slightly faster, less secure) |

Example:
```bash
./axis512 --quiet --kyber
```

---

## 🔬 Detailed Cryptographic Design

### Key Derivation
- Password and optional PIN are concatenated with `"::::"` and processed by **Argon2id** (opslimit: `crypto_pwhash_OPSLIMIT_SENSITIVE`, memory configurable).
- The resulting 32‑byte **master key** is used to unlock further keys.

### Hybrid KEM Mode (default)
1. Generates a **static Kyber‑1024 keypair** and an **X25519 keypair** for the file.
2. The secret keys (`kyber_sk` + `x25519_sk`) are encrypted with the master key using `XChaCha20-Poly1305-IETF` (SKE).
3. A fresh **ephemeral X25519 keypair** is created.
4. **Encapsulation**:  
   `ss_kyber = Kyber.Enc(pk_kyber)`  
   `ss_x25519 = X25519(eph_priv, pk_x25519)`
5. Both shared secrets are combined using **BLAKE2b** keyed with the domain `"AXIS-HYBRID"` to produce the **hybrid shared secret**.
6. The hybrid shared secret is expanded via BLAKE2b (`"AXIS-HYBRID-OUTER"`) to obtain the **derived outer key**.

### Ephemeral Key Mode
- A random 32‑byte key is generated per file, encrypted with the master key, and used directly as the outer key.

### Classic Mode
- The master key itself is used as the outer key.

### JIT Per‑file Outer Key
- Regardless of mode, a **fresh 32‑byte file outer key** is generated and wrapped with the derived outer key using `XChaCha20-Poly1305`.  
- This ensures unique keys for every file, even if the same password is reused.

### Inner Encryption
- A random **inner key** and **inner nonce** are generated.
- They are written to the output file first.
- The inner key initialises an **XChaCha20-Poly1305 secretstream** (libsodium’s `crypto_secretstream_xchacha20poly1305`).
- On the **first chunk only**, the inner nonce is passed as associated data (AD), binding the nonce to the ciphertext.
- File is processed in chunks of 1 MiB, each chunk tagged appropriately (`TAG_MESSAGE` or `TAG_FINAL`).
- All operations O(1) RAM.

### SIV (Synthetic IV)
- Computed over the **plaintext** to prevent certain forms of corruption/malleability.
- Domain separated: `"AXIS-SIV-V2"` + 64‑bit file size (LE) + plaintext content.
- Uses BLAKE2b keyed with the file outer key, producing a 64‑byte SIV.
- During decryption, the SIV is recomputed and compared in constant time.

### Outer Encryption (default: Keccak‑f[1600] sponge)
- The **file outer key** is expanded through **SPIP** (BLAKE2b‑based iterative expansion) to produce round keys for the sponge.
- The SIV is absorbed into the Keccak state.
- **Streaming Keccak sponge**:
  - For each chunk, the sponge is squeezed to generate a keystream which is XORed with the plaintext.
  - Simultaneously, a second state `st_auth` absorbs the ciphertext for authentication.
- After all data, `st_auth` is permuted and a 64‑byte tag is squeezed.
- The tag is appended to the file.
- **Constant‑time**: the permutation uses TMR and branch‑free mask selection when selecting the TMR result.

### Outer Encryption (alternative: AES‑256‑GCM seal)
- For each chunk, the inner ciphertext is encrypted with an **XChaCha20-Poly1305 secretstream** keyed by a derived “XCC key”.
- A **BLAKE2b MAC** (keyed with outer key) is computed over the entire outer ciphertext.
- The MAC is then **sealed** with AES‑256‑GCM using a random nonce and the outer key.
- Requires hardware AES support for speed; falls back to software otherwise.

### SPIP Expansion
- The outer key is expanded via **BLAKE2b** in an iterative loop (default 4M iterations, configurable up to 16M).
- Domain separation varies with quantum/paranoid mode.
- All round keys are derived deterministically and wiped after use.

### Paranoid & Quantum Modes
- **Paranoid Mode** enforces `axis_rounds = 24` and mixes the SPIP state more frequently.
- **Quantum Mode** sets Argon2id memory to 2 GiB and SPIP iterations to 16M, and adds a “QUANTUM” domain string to capacity hardening – it is a classical cost amplifier, not a post‑quantum proof.

### Constant‑Time & Tamper Resistance
- All critical comparisons (TMR voting, SIV check) use `sodium_memcmp`.
- The TMR selection uses a **masked copy** without branches.
- Padding in `absorb_data()` is implemented without secret‑dependent branches.
- The core Keccak permutation remains constant‑time as standard.
- TMR (`axis_permute`) runs the permutation three times and votes on the result; a discrepancy triggers an error, preventing silent hardware fault exploitation.

---

## 🧪 Self‑Tests

On startup, Axis-512 runs a battery of self‑tests covering:

1. Keccak‑f[1600] permutation non‑triviality.
2. SPIP BLAKE2b determinism and key differentiation.
3. JIT key wrap/unwrap and tamper rejection.
4. SIV domain length correctness.
5. Keccak avalanche effect.
6. AES‑256‑GCM round‑trip (if hardware available).
7. SPIP consistency across runs.
8. Constant‑time utility functions (`ct_memcmp`, `ct_is_zero`).

If any test fails, the program aborts with a clear message.

---

## 🧹 Memory Security

- **`mlock()`**: all sensitive buffers (keys, hashes, states) are locked into physical RAM to prevent swapping.
- **`MADV_DONTDUMP` / `MADV_WIPEONFORK`**: applied immediately after allocation.
- **Secure wiping**: `sodium_memzero` + fallback volatile write before freeing.
- **Heap scrubbing**: after each operation, large temporary allocations are scrubbed with random and patterned writes before `free()` (can be disabled with `--no-heap-scrub`).
- **Core dumps** are disabled.

---

## 📁 File Format

The encrypted file layout (simplified, in order):

```
[salt (32)]
[if Kyber:  SKE nonce (24) | enc(kyber_sk + x25519_sk) (32+32+16)]
            [Kyber ct (1568) | eph_pub X25519 (32)]
[if Ephemeral: eph nonce (24) | enc(eph_key) (32+16)]
[JIT wrapped key: nonce (24) | enc(file_outer_key) (32+16)]
[SIV (64)]
[outer encryption stream ...        ]  // includes inner header, inner CT, then outer tag
                                      // exact format depends on outer mode
```

All sizes are fixed; there are no delimiters.

---

## 🤖 Future Enhancements

- PKCS#11 / smartcard / YubiKey support for key storage.
- GUI front‑end.
- Integration with TPM for key protection.
- Formal verification of Keccak sponge layers.

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.  
Kyber‑1024 and libsodium have their own licenses; consult their repositories.

---

## ⚠️ Disclaimer

This software is provided **as‑is** with no warranty. It has not been audited by a third party.  
Use it at your own risk. For extremely sensitive data, consider combining it with full disk encryption and secure hardware tokens.

---

*Axis-512 – Because your files deserve nothing less than Keccak.*  
**Contribute, report issues, or ask questions at the project’s repository.**
