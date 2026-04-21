MODULUS = 0b10011   # x^4 + x + 1

def gf_mult(a: int, b: int) -> int:
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x10:
            a ^= MODULUS
    return result & 0xF

def gf_inv(a: int) -> int:
    if a == 0:
        return 0
    for x in range(1, 16):
        if gf_mult(a, x) == 1:
            return x
    raise ValueError(f"No inverse found for {a}")


SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]

INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def to_nibbles(val: int) -> tuple:
    return (
        (val >> 12) & 0xF,
        (val >>  8) & 0xF,
        (val >>  4) & 0xF,
        (val >>  0) & 0xF,
    )


def from_nibbles(n0: int, n1: int, n2: int, n3: int) -> int:
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


if __name__ == "__main__":
    print("=" * 50)
    print("  Phase 1 — GF(2^4) & S-box self-test")
    print("=" * 50)

    assert gf_mult(0x5, 0x3) == 0xF
    assert gf_mult(0x9, 0x2) == 0x1
    assert gf_mult(0x0, 0x7) == 0x0
    assert gf_mult(0x1, 0xF) == 0xF
    print("  [OK] gf_mult")

    for a in range(1, 16):
        assert gf_mult(a, gf_inv(a)) == 1
    assert gf_inv(0) == 0
    print("  [OK] gf_inv")

    for i in range(16):
        assert INV_SBOX[SBOX[i]] == i
    print("  [OK] SBOX / INV_SBOX")

    for val in [0x0000, 0xFFFF, 0xABCD, 0x1234]:
        assert from_nibbles(*to_nibbles(val)) == val
    print("  [OK] nibble pack/unpack")

    print()
    print("  SBOX     =", [hex(x) for x in SBOX])
    print("  INV_SBOX =", [hex(x) for x in INV_SBOX])
    print()
    print("  All Phase 1 tests passed ✓")
