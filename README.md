## 🔐 Axis-512 v3.0.5‑Keccak – The Unbreakable, Streaming, Post‑Quantum‑Ready File Encryption Tool

<div>
  <img src="https://img.shields.io/badge/language-C-blue" alt="Language: C">
  <img src="https://img.shields.io/badge/standard-C11%20%2B%20POSIX-green" alt="Standard: C11 + POSIX">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License: MIT">
  <img src="https://img.shields.io/badge/security-O(1)%20RAM%2C%20constant--time%2C%20audited-critical" alt="Security: O(1) RAM, constant-time, audited">
  <img src="https://img.shields.io/badge/KEM-Kyber--1024%2BX25519-brightgreen" alt="KEM: Kyber-1024+X25519">
  <img src="https://img.shields.io/badge/Sponge-Keccak--f[1600]-orange" alt="Sponge: Keccak-f[1600]">
  <img src="https://img.shields.io/badge/Streaming-O(1)%20Memory-success" alt="Streaming: O(1) Memory">
  <img src="https://img.shields.io/badge/TMR-Fault%20Detection-red" alt="TMR: Fault Detection">
  <img src="https://img.shields.io/badge/Status-Active%20Research-yellow" alt="Status: Active Research">
</div>

---

### 🚀 What is Axis-512?

Hey! So Axis-512 is a **high‑assurance file encryption/decryption program** that combines modern crypto into a layered, streaming architecture. The cool part? It uses **O(1) memory** – no matter how huge your file is.

Under the hood, it uses:
- 🔁 **Argon2id** for password‑based key derivation (memory‑hard, resistant to GPU attacks)
- 🧬 **Kyber‑1024 (post‑quantum) + X25519** hybrid key encapsulation (or you can use ephemeral keys)
- 🧽 **Keccak‑f[1600]** – yes, the NIST standard sponge – as the outer cipher
- 🔐 **XChaCha20‑Poly1305** secret‑stream for the inner layer
- 🧪 **BLAKE2b** for key expansion and integrity
- ⏱️ **Constant‑time** critical paths – no timing side‑channels
- 🛡️ **Triple Modular Redundancy (TMR)** to detect random hardware faults
- 📦 **Per‑file JIT key wrapping** and **SIV (Synthetic IV)** for authenticated encryption

All of this runs in **O(1) RAM** – we stream everything in chunks, using temporary in‑memory file descriptors.

---

### ✨ Features at a glance

- 🔑 **Hybrid KEM** – Combine Kyber‑1024 (post‑quantum) with X25519 (classical) for the strongest practical key exchange.
- 🧠 **Quantum Preset** – A classical cost amplifier that cranks Argon2id memory to 2 GiB and SPIP iterations to 16M, raising the bar against future quantum adversaries*. *Not a mathematically proven post‑quantum scheme for symmetric layers, but it makes life very hard.
- 📦 **Layered Encryption** – Inner XChaCha20‑Poly1305 secret‑stream + outer Keccak sponge (or optionally AES‑256‑GCM MAC seal).
- 🧪 **Built‑in Self‑Tests** – Extensive startup checks covering the core sponge, SPIP, JIT wrapping, hybrid KEM, and constant‑time utilities.
- ⚡ **Streaming O(1) RAM** – Never loads the whole file into memory. Fixed‑size buffers only.
- 🛡️ **Paranoid Mode** – Locks rounds to 24, enforces higher mixing in SPIP, and adds extra capacity hardening.
- 🔐 **JIT Key Wrapping** – Each file gets a fresh outer key, wrapped with the derived key before encryption.
- 🧹 **Secure Wiping & Heap Scrubbing** – Sensitive buffers are zeroed and scrubbed after use. Heap can be sanitised on exit.
- 🔎 **Fault Detection (TMR)** – Triple‑modular‑redundancy on the sponge permutation catches silent hardware errors.
- 📏 **Constant‑Time Critical Code** – Functions like `axis_permute()` use `sodium_memcmp` and bit‑mask selection – no timing leaks.
- 🖥️ **Interactive Menu** – Full terminal UI with colour, progress bars, and easy settings adjustment.

---

### 🏗️ Architecture (how it all fits together)

Imagine a pipeline:

1. You give a password (and optional PIN). Argon2id turns that into a **Master Key**.
2. That Master Key unlocks either:
   - a **Hybrid KEM** (Kyber‑1024 + X25519) that produces a **Derived Outer Key**, or
   - an **Ephemeral Key** (random per file), or
   - a **Classic** mode (master key used directly).
3. Then a **JIT per‑file outer key** is generated and wrapped with that Derived Outer Key.
4. **Inner Encryption** starts: XChaCha20‑Poly1305 secret‑stream (random inner key & nonce). It streams the plaintext in chunks, O(1) memory.
5. An **SIV (Synthetic IV)** is computed over the inner ciphertext using BLAKE2b, including the file size.
6. **Outer Encryption** (two selectable modes):
   - Default: **Keccak‑f[1600] sponge** – absorbs the SIV, then generates keystream XORed with inner ciphertext, building an authentication tag.
   - Alternative: **AES‑256‑GCM seal** + XChaCha20 stream.
7. The final encrypted file is written – no headers, no magic bytes, just random‑looking data.

Decryption reverses everything: outer → inner → SIV verification → plaintext. All tags and MACs are checked.

---

### 📦 Requirements (what you need)

- A C17 compiler (GCC ≥ 8, Clang ≥ 10)
- **libsodium** ≥ 1.0.18 (must support XChaCha20‑Poly1305, secretstream, Argon2id, etc.)
- **Kyber‑1024 reference implementation** – the code expects `kyber/kem.h` with the standard Kyber‑1024 constants and functions.
- **Linux** (we use `memfd_create`, `mlock`, `MADV_*` – macOS might work with small tweaks).

---

### 🛠️ How to build it

**1. Install libsodium**
```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev
# macOS (Homebrew)
brew install libsodium
```

**2. Prepare Kyber library**  
Place the Kyber‑1024 reference sources in a `kyber/` subdirectory. The header `kyber/kem.h` must define:
- `KYBER_PUBLICKEYBYTES`, `KYBER_SECRETKEYBYTES`, `KYBER_CIPHERTEXTBYTES`, `KYBER_SSBYTES`
- `crypto_kem_keypair()`, `crypto_kem_enc()`, `crypto_kem_dec()`

**3. Compile** (example command)
```bash
gcc -std=c17 -O2 -march=native -fPIE -o axis512 axis.c intern.c \
    -lsodium -lpthread -ldl -lm \
    -I. -Ikyber \
    -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
```
For a fully static binary (portable):
```bash
gcc ... -static -Wl,-Bstatic -lsodium -Wl,-Bdynamic ...
```

**4. Optional hardening flags**  
`-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -pedantic`

---

### 🚀 Usage (running the tool)

Just run the interactive menu:
```bash
./axis512
```

You’ll see a cool ASCII art logo and a menu like:
```
    █████╗ ██╗  ██╗██╗███████╗   ██████╗ ██████╗
   ... (fancy logo) ...

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

- **Encrypt**: choose 1, enter password (and optional PIN), then input/output file paths. The program does the rest.
- **Decrypt**: choose 2, same steps – it auto‑detects everything.
- **Settings** (option 3): you can tweak Argon2id memory, Keccak rounds, SPIP iterations, TMR, Paranoid mode, Ephemeral/Kyber modes, outer cipher, and password visibility.

**Command‑line flags** (handy for scripts):
- `--quiet` or `-q` – suppress progress animations
- `--dry-run` – show what would be done without writing files
- `--ephemeral` – use ephemeral key mode (disables Kyber)
- `--kyber` – force Kyber KEM mode
- `--aes-outer` – use AES‑GCM + XChaCha20 outer layer instead of Keccak
- `--no-heap-scrub` – disable heap scrubbing (faster, less secure)

Example: `./axis512 --quiet --kyber`

---

### 🔬 Deep dive: Cryptographic design (the fun part)

**Key Derivation** – Your password + optional PIN are concatenated with `"::::"` and fed to Argon2id (opslimit sensitive, memory configurable). The result is a 32‑byte **master key**.

**Hybrid KEM Mode (default)**  
- Generate a static Kyber‑1024 keypair and an X25519 keypair for the file.  
- Encrypt the secret keys (`kyber_sk` + `x25519_sk`) with the master key using XChaCha20‑Poly1305.  
- Create a fresh ephemeral X25519 keypair.  
- Encapsulate:  
  `ss_kyber = Kyber.Enc(pk_kyber)`  
  `ss_x25519 = X25519(eph_priv, pk_x25519)`  
- Combine both shared secrets with BLAKE2b keyed with `"AXIS-HYBRID"` to get the **hybrid shared secret**.  
- Expand that with BLAKE2b (`"AXIS-HYBRID-OUTER"`) to obtain the **derived outer key**.

**Ephemeral Key Mode** – a random 32‑byte key per file, encrypted with the master key.

**Classic Mode** – the master key itself is the outer key.

**JIT Per‑file Outer Key** – regardless of mode, a fresh 32‑byte file outer key is generated and wrapped with the derived outer key (XChaCha20‑Poly1305). This guarantees unique keys per file, even if the same password is reused.

**Inner Encryption** – random inner key + inner nonce. Writes them to the output file, then initialises a **libsodium secretstream** (XChaCha20‑Poly1305). On the first chunk only, the inner nonce is passed as associated data. File processed in 1 MiB chunks, each properly tagged. O(1) RAM.

**SIV (Synthetic IV)** – computed over the plaintext (domain `"AXIS-SIV-V2"` + 64‑bit file size + plaintext) using BLAKE2b keyed with the file outer key. Produces a 64‑byte SIV. During decryption, the SIV is recomputed and compared in constant time – this prevents certain types of corruption/malleability.

**Outer Encryption (default Keccak‑f[1600] sponge)**  
- The file outer key is expanded through **SPIP** (BLAKE2b‑based iterative expansion, default 4M iterations) to produce round keys.  
- The SIV is absorbed into the Keccak state.  
- Streaming: for each chunk, squeeze keystream and XOR with plaintext; simultaneously, a second authentication state absorbs the ciphertext.  
- At the end, a 64‑byte tag is squeezed and appended.  
- The permutation uses **TMR** and branch‑free mask selection – constant‑time.

**Outer Encryption (alternative AES‑GCM seal)** – encrypts the inner ciphertext with another XChaCha20 secretstream, then computes a BLAKE2b MAC over the whole outer ciphertext, and finally seals that MAC with AES‑256‑GCM using a random nonce and the outer key. Requires hardware AES for speed.

**SPIP Expansion** – the outer key is expanded via BLAKE2b in an iterative loop (configurable up to 16M iterations). Domain separation changes in quantum/paranoid mode. All round keys are deterministically derived and wiped after use.

**Paranoid & Quantum Modes** – Paranoid forces 24 rounds and more frequent SPIP mixing. Quantum mode sets Argon2id memory to 2 GiB and SPIP iterations to 16M, plus adds a `"QUANTUM"` string to capacity hardening – it’s a **classical cost amplifier**, not a post‑quantum proof.

**Constant‑Time & Tamper Resistance** – all critical comparisons (TMR voting, SIV check) use `sodium_memcmp`. TMR selection uses a masked copy without branches. Padding in `absorb_data()` has no secret‑dependent branches. The Keccak permutation itself is constant‑time. TMR runs the permutation three times and votes; a discrepancy triggers an error – no silent hardware fault exploitation.

---

### 🧪 Self‑tests (what happens when you start the program)

On launch, Axis‑512 runs a full suite of tests:
1. Keccak‑f[1600] permutation non‑triviality.
2. SPIP BLAKE2b determinism and key differentiation.
3. JIT key wrap/unwrap and tamper rejection.
4. SIV domain length correctness.
5. Keccak avalanche effect.
6. AES‑256‑GCM round‑trip (if hardware available).
7. SPIP consistency across runs.
8. Constant‑time utility functions (`ct_memcmp`, `ct_is_zero`).

If any test fails, the program aborts with a clear error message. No silent failures.

---

### 🧹 Memory security (we take this seriously)

- **mlock()** – all sensitive buffers (keys, hashes, states) are locked into physical RAM to prevent swapping.
- **MADV_DONTDUMP / MADV_WIPEONFORK** – applied immediately after allocation.
- **Secure wiping** – `sodium_memzero` plus a fallback volatile write before freeing.
- **Heap scrubbing** – after each operation, large temporary allocations are scrubbed with random and patterned writes before `free()`. You can disable this with `--no-heap-scrub` for speed.
- **Core dumps** are disabled entirely.

---

### 📁 File format (what the encrypted file looks like)

The layout is simple (no delimiters, fixed sizes):

- [salt (32 bytes)]
- if Kyber mode: [SKE nonce (24)] + encrypted(kyber_sk + x25519_sk) (32+32+16) + [Kyber ciphertext (1568)] + [ephemeral X25519 public key (32)]
- if Ephemeral mode: [ephemeral nonce (24)] + encrypted(eph_key) (32+16)
- [JIT wrapped key: nonce (24) + encrypted(file_outer_key) (32+16)]
- [SIV (64 bytes)]
- [outer encryption stream ...] – this includes the inner header, inner ciphertext, and the outer tag. Exact format depends on the outer mode (Keccak or AES).

No magic bytes, no version numbers – it looks like pure random noise.

---

### 🤖 What’s coming next (future enhancements)

- PKCS#11 / smartcard / YubiKey support for key storage.
- A GUI front‑end.
- TPM integration for hardware key protection.
- Formal verification of the Keccak sponge layers.

---

### 📜 License

MIT License. See the LICENSE file for details.  
Kyber‑1024 and libsodium have their own licenses – check their repositories.

---

### ⚠️ Disclaimer

This software is provided **as‑is**, with no warranty. It has not been audited by a third party. Use it at your own risk. For extremely sensitive data, combine it with full disk encryption and secure hardware tokens.

---

*Axis-512 – Because your files deserve nothing less than Keccak.*  
**Contribute, report issues, or ask questions at the project’s repository.** 🔐✨
