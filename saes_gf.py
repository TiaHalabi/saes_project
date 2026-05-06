MODULUS = 0b10011   # Irreducible polynomial: x^4 + x + 1

# GF(2^4) Multiplication
# This function multiplies two 4-bit numbers (nibbles)
# inside the finite field GF(2^4).
# We use:
# - XOR instead of normal addition
# - Polynomial reduction using the modulus
# This is one of the core operations used in S-AES.
def gf_mult(a: int, b: int) -> int:
    result = 0

    # Process each bit of b
    for _ in range(4):

        # If current bit of b is 1,
        # add current value of a to result
        if b & 1:
            result ^= a

        # Move to next bit of b
        b >>= 1

        # Multiply a by x (left shift)
        a <<= 1

        # If degree becomes >= 4,
        # reduce using the irreducible polynomial
        if a & 0x10:
            a ^= MODULUS

    # Keep only 4 bits
    return result & 0xF


# Multiplicative Inverse in GF(2^4)
# Finds x such that:
#     a × x = 1
# Every non-zero element in GF(2^4)
# has a multiplicative inverse.
# This operation is important in cryptography
# and is commonly used when building S-boxes.
def gf_inv(a: int) -> int:

    # Zero has no true inverse,
    # but we return 0 by convention
    if a == 0:
        return 0

    # Brute-force search for inverse
    for x in range(1, 16):

        # Check if multiplication gives 1
        if gf_mult(a, x) == 1:
            return x

    raise ValueError(f"No inverse found for {a}")


# S-BOX (Substitution Box)
# The S-box is a lookup table used for substitution.
# It transforms each nibble into another nibble
# to introduce NON-LINEARITY in encryption.
# This helps strengthen the cipher
# against cryptanalysis attacks.

SBOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

# Inverse S-BOX
# Used during DECRYPTION.
# If:
#     SBOX[a] = b
# then:
#     INV_SBOX[b] = a

INV_SBOX = [0] * 16

for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


# Split 16-bit value into 4 nibbles
# Example:
#     0xABCD → (0xA, 0xB, 0xC, 0xD)
# Useful because S-AES internally works
# on small 4-bit blocks.
def to_nibbles(val: int) -> tuple:
    return (
        (val >> 12) & 0xF,
        (val >>  8) & 0xF,
        (val >>  4) & 0xF,
        (val >>  0) & 0xF,
    )


# Combine 4 nibbles back into a 16-bit value
# Example:
#     (0xA, 0xB, 0xC, 0xD) → 0xABCD
# This reverses the to_nibbles() operation.
def from_nibbles(n0: int, n1: int, n2: int, n3: int) -> int:
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


# MAIN TEST SECTION
# This section verifies that all components work
# correctly before using them in encryption.
# We test:
# 1. GF multiplication
# 2. Multiplicative inverses
# 3. S-box correctness
# 4. Nibble packing/unpacking
if __name__ == "__main__":

    print("=" * 50)
    print("  Phase 1 — GF(2^4) & S-box self-test")
    print("=" * 50)
    
    # Test finite field multiplication
    assert gf_mult(0x5, 0x3) == 0xF
    assert gf_mult(0x9, 0x2) == 0x1
    assert gf_mult(0x0, 0x7) == 0x0
    assert gf_mult(0x1, 0xF) == 0xF

    print("  [OK] gf_mult")

    # Test multiplicative inverses
    # Verify:
    #     a × inverse(a) = 1
    for a in range(1, 16):
        assert gf_mult(a, gf_inv(a)) == 1

    assert gf_inv(0) == 0

    print("  [OK] gf_inv")
    
    # Test S-box and inverse S-box
    # Ensure:
    #     INV_SBOX[SBOX[i]] = i
    for i in range(16):
        assert INV_SBOX[SBOX[i]] == i

    print("  [OK] SBOX / INV_SBOX")

    # Test nibble split and reconstruction
    for val in [0x0000, 0xFFFF, 0xABCD, 0x1234]:
        assert from_nibbles(*to_nibbles(val)) == val

    print("  [OK] nibble pack/unpack")
    
    # Display generated tables
    print()
    print("  SBOX     =", [hex(x) for x in SBOX])
    print("  INV_SBOX =", [hex(x) for x in INV_SBOX])
    print()

    print("  All Phase 1 tests passed ✓")