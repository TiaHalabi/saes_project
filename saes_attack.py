import time
from saes_core import saes_encrypt, saes_decrypt
from saes_ctr import ctr_process


# ---------------------------------------------------
# Known-Plaintext Brute-Force Attack
# ---------------------------------------------------
# This attack assumes the attacker knows:
#
# - one plaintext block
# - its corresponding ciphertext block
#
# In CTR mode:
#
#     Ciphertext = Plaintext XOR Keystream
#
# Therefore:
#
#     Keystream = Plaintext XOR Ciphertext
#
# The attacker brute-forces all possible 16-bit keys
# until the generated keystream matches.
#
# Since S-AES uses only a 16-bit key,
# exhaustive search is practical.
# ---------------------------------------------------
def brute_force_known_plaintext(
    known_pt: int,
    known_ct: int,
    nonce: int = 0,
    verbose: bool = True,
) -> list:

    # Build the first counter block
    counter_block = ((nonce & 0xFF) << 8)

    # Recover the target keystream
    target_keystream = known_pt ^ known_ct

    if verbose:

        print("=" * 58)
        print("  Brute-Force — Known-Plaintext Attack")
        print("=" * 58)

        print(f"  Known PT word   = 0x{known_pt:04X}")
        print(f"  Known CT word   = 0x{known_ct:04X}")
        print(f"  Nonce           = 0x{nonce:02X}")

        print(f"  Target keystream= 0x{target_keystream:04X}")

        print(f"  Searching 2^16 = 65,536 keys …\n")

    candidates = []

    # Start timing attack
    t0 = time.perf_counter()

    # Exhaustive search through all possible keys
    for key in range(0x10000):

        # Generate keystream using candidate key
        if saes_encrypt(counter_block, key) == target_keystream:
            candidates.append(key)

    elapsed = time.perf_counter() - t0

    if verbose:

        print(f"  Finished in {elapsed*1000:.2f} ms")

        if candidates:

            for k in candidates:
                print(f"  ✓  Key found: 0x{k:04X}")

        else:
            print("  ✗  No matching key found.")

    return candidates


# ---------------------------------------------------
# Common File Signatures (Magic Bytes)
# ---------------------------------------------------
# Many file formats begin with predictable bytes.
#
# Examples:
# - PNG  → 89 50
# - JPEG → FF D8
# - ZIP  → 50 4B
#
# Attackers can exploit these known patterns
# during ciphertext-only attacks.
# ---------------------------------------------------
FILE_MAGIC = {

    "txt_saes": b"S-",
    "txt_the": b"Th",

    "png": b"\x89P",
    "jpeg": b"\xFF\xD8",

    "pdf": b"%P",
    "zip": b"PK",
}


# ---------------------------------------------------
# Ciphertext-Only Brute-Force Attack
# ---------------------------------------------------
# In this attack:
#
# - attacker knows ONLY ciphertext
# - attacker guesses likely file header bytes
#
# Using guessed plaintext:
#
#     Keystream = Plaintext XOR Ciphertext
#
# Then brute-force all keys until
# the generated keystream matches.
#
# Demonstrates how predictable file headers
# weaken security in small-key systems.
# ---------------------------------------------------
def brute_force_ciphertext_only(
    ciphertext: bytes,
    nonce: int,
    magic_hint: str = "txt_saes",
    verbose: bool = True,
) -> list:

    # Get expected magic bytes
    magic = FILE_MAGIC.get(magic_hint, b"")

    # Need at least 2 bytes for one S-AES block
    if len(magic) < 2:

        print(f"  [!] Magic hint '{magic_hint}' too short — need 2 bytes")

        return []

    # First ciphertext block
    ct_word0 = (ciphertext[0] << 8) | ciphertext[1]

    # Expected plaintext block from magic bytes
    pt_word0 = (magic[0] << 8) | magic[1]

    # Recover target keystream
    target_ks = pt_word0 ^ ct_word0

    # Counter block for CTR mode
    counter_block = (nonce & 0xFF) << 8

    if verbose:

        print("=" * 58)
        print("  Brute-Force — Ciphertext-Only Attack (magic bytes)")
        print("=" * 58)

        print(f"  Magic hint      = '{magic_hint}'  → 0x{pt_word0:04X}")

        print(f"  First CT word   = 0x{ct_word0:04X}")

        print(f"  Target keystream= 0x{target_ks:04X}")

        print()

    candidates = []

    # Start timing attack
    t0 = time.perf_counter()

    # Try every possible key
    for key in range(0x10000):

        # Check if generated keystream matches
        if saes_encrypt(counter_block, key) == target_ks:
            candidates.append(key)

    elapsed = time.perf_counter() - t0

    if verbose:

        print(f"  Finished in {elapsed*1000:.2f} ms")

        # Evaluate candidate keys
        for k in candidates:

            # Attempt decryption
            recovered = ctr_process(ciphertext, k, nonce)

            # Estimate how readable plaintext is
            readable = sum(
                32 <= b < 127 or b in (9, 10, 13)
                for b in recovered
            )

            score = readable / len(recovered) * 100

            print(
                f"  ✓  Key candidate: 0x{k:04X}  "
                f"(printable score: {score:.0f}%)"
            )

            # Show likely successful decryptions
            if score > 80:
                print(f"     Decrypted: {recovered[:60]}")

    return candidates


# ---------------------------------------------------
# Nonce-Reuse Attack
# ---------------------------------------------------
# If the SAME nonce and key are reused:
#
#     C1 = P1 XOR KS
#     C2 = P2 XOR KS
#
# Then:
#
#     C1 XOR C2 = P1 XOR P2
#
# The keystream cancels out.
#
# This leaks information about plaintexts.
# ---------------------------------------------------
def nonce_reuse_attack(ct1: bytes, ct2: bytes) -> bytes:

    # Use shortest ciphertext length
    length = min(len(ct1), len(ct2))

    # XOR ciphertexts together
    return bytes(
        a ^ b
        for a, b in zip(ct1[:length], ct2[:length])
    )


# ---------------------------------------------------
# Recover Unknown Plaintext
# ---------------------------------------------------
# If attacker knows:
#
# - P1
# - C1 XOR C2
#
# Then:
#
#     P2 = (C1 XOR C2) XOR P1
#
# Demonstrates why nonce reuse is dangerous.
# ---------------------------------------------------
def nonce_reuse_recover(
    xor_stream: bytes,
    known_pt1: bytes
) -> bytes:

    length = min(len(xor_stream), len(known_pt1))

    return bytes(
        x ^ p
        for x, p in zip(
            xor_stream[:length],
            known_pt1[:length]
        )
    )


# ---------------------------------------------------
# MAIN TEST SECTION
# ---------------------------------------------------
# Demonstrates:
#
# 1. Known-plaintext attack
# 2. Ciphertext-only attack
# 3. Nonce reuse attack
#
# Shows why:
# - small keys are insecure
# - nonce reuse must NEVER happen
# ---------------------------------------------------
if __name__ == "__main__":

    SECRET_KEY = 0x2B7E
    NONCE = 0xA3

    plaintext = b"S-AES CTR mode project"

    # Encrypt target plaintext
    ciphertext = ctr_process(
        plaintext,
        SECRET_KEY,
        NONCE
    )


    # -----------------------------------------------
    # Known-Plaintext Attack Demo
    # -----------------------------------------------

    # Extract first plaintext block
    known_pt_word = (
        (plaintext[0] << 8) |
        plaintext[1]
    )

    # Extract first ciphertext block
    known_ct_word = (
        (ciphertext[0] << 8) |
        ciphertext[1]
    )

    # Recover key candidates
    candidates = brute_force_known_plaintext(
        known_pt_word,
        known_ct_word,
        NONCE
    )

    # Use recovered key to decrypt full message
    if candidates:

        recovered = ctr_process(
            ciphertext,
            candidates[0],
            NONCE
        )

        print(f"\n  Full message recovered: {recovered}\n")

        assert recovered == plaintext


    print()


    # -----------------------------------------------
    # Ciphertext-Only Attack Demo
    # -----------------------------------------------
    candidates2 = brute_force_ciphertext_only(
        ciphertext,
        NONCE,
        magic_hint="txt_saes"
    )


    print()

    print("=" * 58)
    print("  Nonce-Reuse Attack Demo")
    print("=" * 58)

    # Two messages encrypted with SAME nonce
    p1 = b"HELLO WORLD!!!!!"
    p2 = b"SECRET MESSAGE!!"

    c1 = ctr_process(p1, SECRET_KEY, NONCE)
    c2 = ctr_process(p2, SECRET_KEY, NONCE)

    # XOR ciphertexts together
    xor_stream = nonce_reuse_attack(c1, c2)

    # Recover secret plaintext using known plaintext
    p2_recovered = nonce_reuse_recover(
        xor_stream,
        p1
    )

    print(f"  P1 (known)     = {p1}")

    print(f"  P2 (secret)    = {p2}")

    print(f"  C1 ⊕ C2        = {xor_stream.hex()}")

    print(f"  P2 recovered   = {p2_recovered}")

    assert p2_recovered == p2

    print("  [OK] Nonce-reuse recovery successful ✓")

    print("\n  All Phase 4 tests passed ✓")