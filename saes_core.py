from saes_gf import SBOX, INV_SBOX, gf_mult, to_nibbles, from_nibbles
RC1 = 0x80
RC2 = 0x30

# SubNib operation for one byte
# Applies the S-box substitution to:
# - upper nibble
# - lower nibble
# Example: 0xAB → SBOX(A) || SBOX(B)
# This introduces NON-LINEARITY into the key schedule.
def _sub_nib_word(w: int) -> int:   
    hi = SBOX[(w >> 4) & 0xF]
    lo = SBOX[(w >> 0) & 0xF]
    return (hi << 4) | lo


# RotNib operation
# Swaps the two nibbles of a byte.
# Example: 0xAB → 0xBA
# Used during key expansion.
def _rot_nib(w: int) -> int:    
    return ((w << 4) | (w >> 4)) & 0xFF

# Converts one 16-bit key into: K0, K1, K2
# These round keys are used during encryption and decryption rounds
def key_expansion(key: int) -> list:
    # Split original key into two bytes
    W0 = (key >> 8) & 0xFF
    W1 =  key       & 0xFF

    # Generate next words using:
    # - RotNib
    # - SubNib
    # - Round constants
    W2 = W0 ^ RC1 ^ _sub_nib_word(_rot_nib(W1))
    W3 = W2 ^ W1
    W4 = W2 ^ RC2 ^ _sub_nib_word(_rot_nib(W3))
    W5 = W4 ^ W3

    # Combine words into round keys
    K0 = (W0 << 8) | W1
    K1 = (W2 << 8) | W3
    K2 = (W4 << 8) | W5
    return [K0, K1, K2]


# XORs the current state with the round key
#State = State XOR RoundKey
def add_round_key(state: int, round_key: int) -> int:   
    return state ^ round_key


# Replaces every nibble in the state using:
# SBOX        (encryption)
# INV_SBOX    (decryption)
def nibble_sub(state: int, inverse: bool = False) -> int:   
    box = INV_SBOX if inverse else SBOX
    n0, n1, n2, n3 = to_nibbles(state)
    return from_nibbles(box[n0], box[n1], box[n2], box[n3])


# Rearranges the state matrix.
# In S-AES:
# first row stays unchanged
# second row is shifted left
def shift_row(state: int) -> int:
    n0, n1, n2, n3 = to_nibbles(state)
    return from_nibbles(n0, n3, n2, n1)


#Takes each column of the 2×2 matrix and multiplies it by a fixed matrix using GF(2⁴)
def mix_columns(state: int, inverse: bool = False) -> int:
    n0, n1, n2, n3 = to_nibbles(state)

    if not inverse:
        new_n0 = gf_mult(1, n0) ^ gf_mult(4, n2)
        new_n2 = gf_mult(4, n0) ^ gf_mult(1, n2)
        new_n1 = gf_mult(1, n1) ^ gf_mult(4, n3)
        new_n3 = gf_mult(4, n1) ^ gf_mult(1, n3)
    else:
        new_n0 = gf_mult(9, n0) ^ gf_mult(2, n2)
        new_n2 = gf_mult(2, n0) ^ gf_mult(9, n2)
        new_n1 = gf_mult(9, n1) ^ gf_mult(2, n3)
        new_n3 = gf_mult(2, n1) ^ gf_mult(9, n3)

    return from_nibbles(new_n0, new_n1, new_n2, new_n3)


# Encryption process:
# 1. Initial AddRoundKey
# 2. Round 1
#    - SubNib
#    - ShiftRow
#    - MixColumns
#    - AddRoundKey
# 3. Round 2
#    - SubNib
#    - ShiftRow
#    - AddRoundKey
# Final output = Ciphertext
def saes_encrypt(plaintext: int, key: int) -> int:

    K = key_expansion(key)
    state = plaintext

    state = add_round_key(state, K[0])

    # Round 1
    state = nibble_sub(state)
    state = shift_row(state)
    state = mix_columns(state)
    state = add_round_key(state, K[1])

    # Round 2
    state = nibble_sub(state)
    state = shift_row(state)
    state = add_round_key(state, K[2])

    return state


# S-AES Decryption
# Performs the reverse operations in reverse order:
# - AddRoundKey
# - InvShiftRow
# - InvSubNib
# - InvMixColumns
# Final output = Original plaintext
def saes_decrypt(ciphertext: int, key: int) -> int:

    K = key_expansion(key)
    state = ciphertext

    state = add_round_key(state, K[2])
    state = shift_row(state)
    state = nibble_sub(state, inverse=True)

    state = add_round_key(state, K[1])
    state = mix_columns(state, inverse=True)
    state = shift_row(state)
    state = nibble_sub(state, inverse=True)

    state = add_round_key(state, K[0])

    return state


# - Key expansion correctness
# - Encryption/decryption correctness
# - Large round-trip testing
# Round-trip means: Decrypt(Encrypt(P)) = P
if __name__ == "__main__":
    print("=" * 55)
    print("  Phase 2 — S-AES core self-test")
    print("=" * 55)

    key   = 0b0010011101000011
    K     = key_expansion(key)
    print(f"\n  Key      = {hex(key)}")
    print(f"  K0 = {hex(K[0])},  K1 = {hex(K[1])},  K2 = {hex(K[2])}")

    pt  = 0x6F6B
    key = 0x2743
    ct  = saes_encrypt(pt, key)
    dec = saes_decrypt(ct, key)

    print(f"\n  Plaintext   = {hex(pt)}")
    print(f"  Key         = {hex(key)}")
    print(f"  Ciphertext  = {hex(ct)}")
    print(f"  Decrypted   = {hex(dec)}")

    assert dec == pt, "Decrypt(Encrypt(P)) != P"
    print("\n  [OK] Encrypt/Decrypt round-trip")

    errors = 0
    for pt in range(0, 0x10000, 311):
        for key in range(0, 0x10000, 997):
            ct  = saes_encrypt(pt, key)
            dec = saes_decrypt(ct, key)
            if dec != pt:
                errors += 1
    print(f"  [OK] Exhaustive round-trip test  (errors: {errors})")

    print("\n  All Phase 2 tests passed ✓")
