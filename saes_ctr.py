import os
import struct
from saes_core import saes_encrypt


# ---------------------------------------------------
# CTR Mode Counter Block
# ---------------------------------------------------
# Creates the input block for S-AES encryption.
#
# Structure:
#     [ NONCE | COUNTER ]
#
# - Nonce changes for every encryption session
# - Counter increments for every block
#
# This guarantees a different keystream block
# for every plaintext block.
# ---------------------------------------------------
def _ctr_block(key: int, nonce: int, counter: int) -> int:

    # Combine nonce and counter into one 16-bit block
    counter_block = ((nonce & 0xFF) << 8) | (counter & 0xFF)

    # Encrypt the counter block to generate keystream
    return saes_encrypt(counter_block, key)


# ---------------------------------------------------
# CTR Mode Processing
# ---------------------------------------------------
# CTR mode uses encryption for BOTH:
# - encryption
# - decryption
#
# Formula:
#
#     Ciphertext = Plaintext XOR Keystream
#
# Since XOR is reversible:
#
#     Plaintext = Ciphertext XOR Keystream
#
# This function works for both operations.
# ---------------------------------------------------
def ctr_process(data: bytes, key: int, nonce: int) -> bytes:

    output = bytearray()

    # Pad odd-length data with one null byte
    # because S-AES works on 16-bit blocks
    padded = data if len(data) % 2 == 0 else data + b'\x00'

    # Process 2 bytes at a time
    for i in range(0, len(padded), 2):

        # Counter value for current block
        counter = (i // 2) & 0xFF

        # Generate keystream block
        keystream = _ctr_block(key, nonce, counter)

        # Convert plaintext bytes into 16-bit word
        pt_word = (padded[i] << 8) | padded[i + 1]

        # XOR plaintext with keystream
        ct_word = pt_word ^ keystream

        # Store encrypted/decrypted bytes
        output.append((ct_word >> 8) & 0xFF)
        output.append(ct_word & 0xFF)

    # Remove possible padding byte
    return bytes(output[:len(data)])


# ---------------------------------------------------
# File Encryption
# ---------------------------------------------------
# Reads a file, encrypts its content using CTR mode,
# then saves:
#
# [ nonce | original_length | ciphertext ]
#
# Header information is stored so the file
# can later be decrypted correctly.
# ---------------------------------------------------
def encrypt_file(input_path: str,
                 output_path: str,
                 key: int,
                 nonce: int) -> None:

    # Read plaintext file
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt data using CTR mode
    ciphertext = ctr_process(plaintext, key, nonce)

    # Write encrypted file
    with open(output_path, 'wb') as f:

        # Store nonce and original length in header
        f.write(bytes([
            nonce & 0xFF,
            len(plaintext) & 0xFF
        ]))

        # Store ciphertext
        f.write(ciphertext)

    print(f"[ENCRYPT] {input_path}  →  {output_path}")

    print(
        f"          key=0x{key:04X}  "
        f"nonce=0x{nonce:02X}  "
        f"plaintext={len(plaintext)} bytes  "
        f"ciphertext={len(ciphertext)} bytes"
    )


# ---------------------------------------------------
# File Decryption
# ---------------------------------------------------
# Reads encrypted file:
#
# [ nonce | original_length | ciphertext ]
#
# Then reconstructs the original plaintext.
# ---------------------------------------------------
def decrypt_file(input_path: str,
                 output_path: str,
                 key: int) -> None:

    # Read encrypted file
    with open(input_path, 'rb') as f:

        # First 2 bytes = header
        header = f.read(2)

        # Remaining bytes = ciphertext
        ciphertext = f.read()

    # Extract stored nonce
    nonce = header[0]

    # Extract original plaintext length
    orig_len = header[1]

    # Decrypt using CTR mode
    plaintext = ctr_process(ciphertext, key, nonce)

    # Remove extra padding byte if needed
    if len(ciphertext) > orig_len and (len(plaintext) - orig_len) == 1:
        plaintext = plaintext[:orig_len]

    # Save recovered plaintext
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"[DECRYPT] {input_path}  →  {output_path}")

    print(
        f"          key=0x{key:04X}  "
        f"nonce=0x{nonce:02X}  "
        f"recovered={len(plaintext)} bytes"
    )


# ---------------------------------------------------
# Hex Dump Utility
# ---------------------------------------------------
# Displays binary data in:
# - hexadecimal format
# - ASCII format
#
# Useful for visualizing:
# - plaintext
# - ciphertext
# - recovered data
# ---------------------------------------------------
def hex_dump(data: bytes,
             label: str = "",
             width: int = 16) -> None:

    if label:
        print(f"\n  {label}")
        print("  " + "-" * (width * 3 + 2))

    # Process data line by line
    for i in range(0, len(data), width):

        chunk = data[i:i + width]

        # Hexadecimal representation
        hex_part = " ".join(f"{b:02X}" for b in chunk)

        # ASCII representation
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "."
            for b in chunk
        )

        print(
            f"  {i:04X}  "
            f"{hex_part:<{width*3}}  "
            f"{ascii_part}"
        )


# ---------------------------------------------------
# MAIN TEST SECTION
# ---------------------------------------------------
# Verifies:
# - CTR encryption/decryption
# - Different keys behavior
# - Nonce reuse property
# - File encryption/decryption
#
# CTR mode turns a block cipher into
# a stream cipher.
# ---------------------------------------------------
if __name__ == "__main__":

    import tempfile, os

    print("=" * 55)
    print("  Phase 3 — CTR mode self-test")
    print("=" * 55)

    # -----------------------------------------------
    # Test parameters
    # -----------------------------------------------
    KEY = 0x2B7E
    NONCE = 0xA3


    # -----------------------------------------------
    # In-memory encryption/decryption tests
    # Tests different message lengths
    # -----------------------------------------------
    messages = [
        b"Hello, S-AES!",
        b"A",
        b"ABCDEFGHIJKLMNOP",
        b"Security project CTR mode",
    ]

    for msg in messages:

        # Encrypt
        ct = ctr_process(msg, KEY, NONCE)

        # Decrypt
        dec = ctr_process(ct, KEY, NONCE)

        # Verify original message is restored
        assert dec == msg, f"Round-trip failed for: {msg}"

    print("\n  [OK] In-memory CTR round-trip (all lengths)")


    # -----------------------------------------------
    # Verify different keys produce
    # different ciphertexts
    # -----------------------------------------------
    msg = b"Test message"

    ct1 = ctr_process(msg, 0x1234, NONCE)
    ct2 = ctr_process(msg, 0x5678, NONCE)

    assert ct1 != ct2

    print("  [OK] Different keys produce different ciphertexts")


    # -----------------------------------------------
    # Demonstrate nonce reuse property
    # -----------------------------------------------
    # If the SAME nonce is reused:
    #
    #     C1 XOR C2 = P1 XOR P2
    #
    # This is a known weakness in CTR mode.
    # -----------------------------------------------
    p1 = b"HELLO!!!"
    p2 = b"SECRET!!"

    c1 = ctr_process(p1, KEY, NONCE)
    c2 = ctr_process(p2, KEY, NONCE)

    xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
    xor_pt = bytes(a ^ b for a, b in zip(p1, p2))

    assert xor_ct == xor_pt, \
        "Nonce reuse XOR property failed"

    print("  [OK] Nonce-reuse XOR property verified "
          "(C1⊕C2 = P1⊕P2)")


    # -----------------------------------------------
    # File encryption/decryption test
    # -----------------------------------------------
    with tempfile.TemporaryDirectory() as tmpdir:

        pt_path = os.path.join(tmpdir, "plain.txt")
        enc_path = os.path.join(tmpdir, "cipher.enc")
        dec_path = os.path.join(tmpdir, "decrypted.txt")

        original = (
            b"S-AES CTR mode project\n"
            b"Group implementation\n"
            b"LAU EECE department"
        )

        # Create plaintext test file
        with open(pt_path, 'wb') as f:
            f.write(original)

        print()

        # Encrypt file
        encrypt_file(pt_path, enc_path, KEY, NONCE)

        # Decrypt file
        decrypt_file(enc_path, dec_path, KEY)

        # Read recovered plaintext
        with open(dec_path, 'rb') as f:
            recovered = f.read()

        # Verify recovered file matches original
        assert recovered == original, \
            f"File round-trip failed!\n" \
            f"Original : {original}\n" \
            f"Recovered: {recovered}"

        print("\n  [OK] File encrypt/decrypt round-trip")


        # -------------------------------------------
        # Display plaintext/ciphertext visually
        # -------------------------------------------
        with open(enc_path, 'rb') as f:
            enc_bytes = f.read()

        hex_dump(original,      "Plaintext  (ASCII)")
        hex_dump(enc_bytes[2:], "Ciphertext (hex)")
        hex_dump(recovered,     "Recovered  (ASCII)")


    print("\n  All Phase 3 tests passed ✓")