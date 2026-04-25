import os
import struct
from saes_core import saes_encrypt

def _ctr_block(key: int, nonce: int, counter: int) -> int:
    counter_block = ((nonce & 0xFF) << 8) | (counter & 0xFF)
    return saes_encrypt(counter_block, key)


def ctr_process(data: bytes, key: int, nonce: int) -> bytes:
    output = bytearray()
    padded = data if len(data) % 2 == 0 else data + b'\x00'

    for i in range(0, len(padded), 2):
        counter   = (i // 2) & 0xFF
        keystream = _ctr_block(key, nonce, counter)

        pt_word   = (padded[i] << 8) | padded[i + 1]
        ct_word   = pt_word ^ keystream

        output.append((ct_word >> 8) & 0xFF)
        output.append( ct_word       & 0xFF)

    return bytes(output[:len(data)])


def encrypt_file(input_path: str, output_path: str, key: int, nonce: int) -> None:
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = ctr_process(plaintext, key, nonce)

    with open(output_path, 'wb') as f:
        f.write(bytes([nonce & 0xFF, len(plaintext) & 0xFF]))
        f.write(ciphertext)

    print(f"[ENCRYPT] {input_path}  →  {output_path}")
    print(f"          key=0x{key:04X}  nonce=0x{nonce:02X}  "
          f"plaintext={len(plaintext)} bytes  ciphertext={len(ciphertext)} bytes")


def decrypt_file(input_path: str, output_path: str, key: int) -> None:
    with open(input_path, 'rb') as f:
        header    = f.read(2)
        ciphertext = f.read()

    nonce      = header[0]
    orig_len   = header[1]

    plaintext  = ctr_process(ciphertext, key, nonce)

    if len(ciphertext) > orig_len and (len(plaintext) - orig_len) == 1:
        plaintext = plaintext[:orig_len]

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"[DECRYPT] {input_path}  →  {output_path}")
    print(f"          key=0x{key:04X}  nonce=0x{nonce:02X}  "
          f"recovered={len(plaintext)} bytes")


def hex_dump(data: bytes, label: str = "", width: int = 16) -> None:
    if label:
        print(f"\n  {label}")
        print("  " + "-" * (width * 3 + 2))
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04X}  {hex_part:<{width*3}}  {ascii_part}")


if __name__ == "__main__":
    import tempfile, os

    print("=" * 55)
    print("  Phase 3 — CTR mode self-test")
    print("=" * 55)

    KEY   = 0x2B7E
    NONCE = 0xA3

    messages = [
        b"Hello, S-AES!",
        b"A",
        b"ABCDEFGHIJKLMNOP",
        b"Security project CTR mode",
    ]
    for msg in messages:
        ct  = ctr_process(msg, KEY, NONCE)
        dec = ctr_process(ct,  KEY, NONCE)
        assert dec == msg, f"Round-trip failed for: {msg}"
    print("\n  [OK] In-memory CTR round-trip (all lengths)")

    msg = b"Test message"
    ct1 = ctr_process(msg, 0x1234, NONCE)
    ct2 = ctr_process(msg, 0x5678, NONCE)
    assert ct1 != ct2
    print("  [OK] Different keys produce different ciphertexts")

    p1 = b"HELLO!!!"
    p2 = b"SECRET!!"
    c1 = ctr_process(p1, KEY, NONCE)
    c2 = ctr_process(p2, KEY, NONCE)
    xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
    xor_pt = bytes(a ^ b for a, b in zip(p1, p2))
    assert xor_ct == xor_pt, "Nonce reuse XOR property failed"
    print("  [OK] Nonce-reuse XOR property verified (C1⊕C2 = P1⊕P2)")

    with tempfile.TemporaryDirectory() as tmpdir:
        pt_path  = os.path.join(tmpdir, "plain.txt")
        enc_path = os.path.join(tmpdir, "cipher.enc")
        dec_path = os.path.join(tmpdir, "decrypted.txt")

        original = b"S-AES CTR mode project\nGroup implementation\nLAU EECE department"
        with open(pt_path, 'wb') as f:
            f.write(original)

        print()
        encrypt_file(pt_path, enc_path, KEY, NONCE)
        decrypt_file(enc_path, dec_path, KEY)

        with open(dec_path, 'rb') as f:
            recovered = f.read()

        assert recovered == original, \
            f"File round-trip failed!\nOriginal : {original}\nRecovered: {recovered}"
        print("\n  [OK] File encrypt/decrypt round-trip")

        with open(enc_path, 'rb') as f:
            enc_bytes = f.read()
        hex_dump(original,      "Plaintext  (ASCII)")
        hex_dump(enc_bytes[2:], "Ciphertext (hex)")
        hex_dump(recovered,     "Recovered  (ASCII)")

    print("\n  All Phase 3 tests passed ✓")
