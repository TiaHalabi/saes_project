# S-AES CTR

Implementation of Simplified AES (S-AES) in CTR (Counter) mode from scratch in Python, including a brute-force cryptanalysis attack.

> Note: No standard AES/DES libraries are used. All arithmetic, S-box, key expansion, and cipher operations are implemented manually.

---

## GitHub Repository: https://github.com/TiaHalabi/saes_project.git

----

## Project Structure

| `saes_gf.py` | GF(2⁴) arithmetic, S-box, nibble helpers |
| `saes_core.py` | S-AES encrypt/decrypt (single 16-bit block) |
| `saes_ctr.py` | CTR mode — file encrypt/decrypt |
| `saes_attack.py` | Brute-force & nonce-reuse attack |
| `main.py` | CLI entry point |

---

## How to Run

### Requirements
- Python 3.8+
- No external libraries needed

### Run the full demo
python main.py demo

This encrypts a sample message, runs the brute-force attack to recover the key, then decrypts and verifies.

### Encrypt a file
python main.py encrypt secret.txt secret.enc 0x2B7E 0xA3

Arguments: `<input.txt>` `<output.enc>` `<key_hex>` `<nonce_hex>`

- Key: 16-bit hex value (0x0000–0xFFFF)
- Nonce: 8-bit hex value (0x00–0xFF)

### Decrypt a file
python main.py decrypt secret.enc recovered.txt 0x2B7E

### Run the brute-force attack
python main.py attack secret.enc txt_saes

Magic hints: `txt_saes`, `txt_the`, `png`, `jpeg`, `pdf`, `zip`

### Run unit tests for each phase

python saes_gf.py       # Phase 1 tests
python saes_core.py     # Phase 2 tests
python saes_ctr.py      # Phase 3 tests
python saes_attack.py   # Phase 4 tests

---

## Algorithm Overview

### S-AES
- Block size: 16 bits (2×2 matrix of 4-bit nibbles)
- Key size: 16 bits
- Rounds: 2

Round structure:

AddRoundKey(K0)
Round 1: NibbleSub → ShiftRow → MixColumns → AddRoundKey(K1)
Round 2: NibbleSub → ShiftRow → AddRoundKey(K2)   ← no MixColumns


Key expansion generates K0, K1, K2 from the 16-bit key using RotNib, SubNib, and round constants.

Field arithmetic uses GF(2⁴) with irreducible polynomial x⁴ + x + 1 (0x13).

### CTR Mode

Counter_block_i = Nonce (8 bits) ∥ Counter_i (8 bits)
Keystream_i     = S-AES_K( Counter_block_i )
Ciphertext_i    = Plaintext_i ⊕ Keystream_i

Decryption is identical to encryption — no inverse cipher needed.

### File Format (.enc)

Byte 0      : nonce (8-bit)
Byte 1      : original plaintext length mod 256
Bytes 2..N  : ciphertext


---

## Cryptanalysis

### Brute-Force (Known-Plaintext)
Since the keyspace is only 2¹⁶ = 65,536, exhaustive search completes in ~500 ms.

Strategy: Given one known plaintext/ciphertext block pair and the nonce:

target_keystream = pt_word ⊕ ct_word
Search all K: S-AES_K(nonce ∥ 0) == target_keystream


### Ciphertext-Only (File Magic)
If the file type is known (e.g., starts with `S-` for our format), the first 2 bytes act as a known plaintext, enabling the same attack without explicit knowledge of the plaintext.

### Nonce-Reuse Attack
If two messages are encrypted with the same key and nonce:

C1 ⊕ C2 = P1 ⊕ P2

Knowing P1 immediately reveals P2. This is a critical vulnerability — never reuse a nonce.

---

## Reference
Stallings, W. *Cryptography and Network Security*, Appendix G — Simplified AES.
