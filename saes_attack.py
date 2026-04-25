import time
from saes_core  import saes_encrypt, saes_decrypt
from saes_ctr   import ctr_process

def brute_force_known_plaintext(
    known_pt: int,
    known_ct: int,
    nonce: int = 0,
    verbose: bool = True,
) -> list:
    counter_block    = ((nonce & 0xFF) << 8)
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
    t0 = time.perf_counter()

    for key in range(0x10000):
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

FILE_MAGIC = {
    "txt_saes": b"S-",
    "txt_the" : b"Th",
    "png"     : b"\x89P",
    "jpeg"    : b"\xFF\xD8",
    "pdf"     : b"%P",
    "zip"     : b"PK",
}


def brute_force_ciphertext_only(
    ciphertext: bytes,
    nonce: int,
    magic_hint: str = "txt_saes",
    verbose: bool = True,
) -> list:
    magic = FILE_MAGIC.get(magic_hint, b"")
    if len(magic) < 2:
        print(f"  [!] Magic hint '{magic_hint}' too short — need 2 bytes")
        return []

    ct_word0       = (ciphertext[0] << 8) | ciphertext[1]
    pt_word0       = (magic[0]      << 8) | magic[1]
    target_ks      = pt_word0 ^ ct_word0
    counter_block  = (nonce & 0xFF) << 8

    if verbose:
        print("=" * 58)
        print("  Brute-Force — Ciphertext-Only Attack (magic bytes)")
        print("=" * 58)
        print(f"  Magic hint      = '{magic_hint}'  → 0x{pt_word0:04X}")
        print(f"  First CT word   = 0x{ct_word0:04X}")
        print(f"  Target keystream= 0x{target_ks:04X}")
        print()

    candidates = []
    t0 = time.perf_counter()
    for key in range(0x10000):
        if saes_encrypt(counter_block, key) == target_ks:
            candidates.append(key)
    elapsed = time.perf_counter() - t0

    if verbose:
        print(f"  Finished in {elapsed*1000:.2f} ms")
        for k in candidates:
            recovered = ctr_process(ciphertext, k, nonce)
            readable  = sum(32 <= b < 127 or b in (9, 10, 13) for b in recovered)
            score     = readable / len(recovered) * 100
            print(f"  ✓  Key candidate: 0x{k:04X}  "
                  f"(printable score: {score:.0f}%)")
            if score > 80:
                print(f"     Decrypted: {recovered[:60]}")

    return candidates

def nonce_reuse_attack(ct1: bytes, ct2: bytes) -> bytes:
    length = min(len(ct1), len(ct2))
    return bytes(a ^ b for a, b in zip(ct1[:length], ct2[:length]))


def nonce_reuse_recover(xor_stream: bytes, known_pt1: bytes) -> bytes:
    length = min(len(xor_stream), len(known_pt1))
    return bytes(x ^ p for x, p in zip(xor_stream[:length], known_pt1[:length]))

if __name__ == "__main__":

    SECRET_KEY = 0x2B7E
    NONCE      = 0xA3
    plaintext  = b"S-AES CTR mode project"

    ciphertext = ctr_process(plaintext, SECRET_KEY, NONCE)

    known_pt_word = (plaintext[0] << 8) | plaintext[1]
    known_ct_word = (ciphertext[0] << 8) | ciphertext[1]

    candidates = brute_force_known_plaintext(
        known_pt_word, known_ct_word, NONCE
    )
    if candidates:
        recovered = ctr_process(ciphertext, candidates[0], NONCE)
        print(f"\n  Full message recovered: {recovered}\n")
        assert recovered == plaintext

    print()
    candidates2 = brute_force_ciphertext_only(
        ciphertext, NONCE, magic_hint="txt_saes"
    )

    print()
    print("=" * 58)
    print("  Nonce-Reuse Attack Demo")
    print("=" * 58)
    p1 = b"HELLO WORLD!!!!!"
    p2 = b"SECRET MESSAGE!!"
    c1 = ctr_process(p1, SECRET_KEY, NONCE)
    c2 = ctr_process(p2, SECRET_KEY, NONCE)

    xor_stream = nonce_reuse_attack(c1, c2)
    p2_recovered = nonce_reuse_recover(xor_stream, p1)

    print(f"  P1 (known)     = {p1}")
    print(f"  P2 (secret)    = {p2}")
    print(f"  C1 ⊕ C2        = {xor_stream.hex()}")
    print(f"  P2 recovered   = {p2_recovered}")
    assert p2_recovered == p2
    print("  [OK] Nonce-reuse recovery successful ✓")

    print("\n  All Phase 4 tests passed ✓")
