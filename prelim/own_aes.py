"""Minimalna, edukacyjna implementacja AES-128 (FIPS-197) w czystym Pythonie.
Służy WYŁĄCZNIE do wstępnych testów przydatności – nie używać produkcyjnie."""

SBOX = [0] * 256
INV_SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        # p *= 3 w GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # q /= 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        x = (x ^ 0x63) & 0xFF
        SBOX[p] = x
        INV_SBOX[x] = p
        if p == 1:
            break
    SBOX[0] = 0x63
    INV_SBOX[0x63] = 0


_init_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def expand_key(key: bytes):
    assert len(key) == 16
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[r * 4:(r + 1) * 4], []) for r in range(11)]


def _mix(s):
    for c in range(4):
        a = s[c * 4:c * 4 + 4]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        s[c * 4 + 0] ^= t ^ xtime(a[0] ^ a[1])
        s[c * 4 + 1] ^= t ^ xtime(a[1] ^ a[2])
        s[c * 4 + 2] ^= t ^ xtime(a[2] ^ a[3])
        s[c * 4 + 3] ^= t ^ xtime(a[3] ^ u)


def _shift(s):
    return [s[(i + 4 * (i % 4)) % 16] for i in range(16)]


def encrypt_block(block: bytes, rk) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 10):
        s = _shift([SBOX[b] for b in s])
        _mix(s)
        s = [b ^ k for b, k in zip(s, rk[r])]
    s = _shift([SBOX[b] for b in s])
    return bytes(b ^ k for b, k in zip(s, rk[10]))


def encrypt_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    rk = expand_key(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = encrypt_block(nonce[:8] + (i // 16).to_bytes(8, "big"), rk)
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


if __name__ == "__main__":
    # Wektor testowy FIPS-197, Appendix C.1
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    p = bytes.fromhex("00112233445566778899aabbccddeeff")
    c = encrypt_block(p, expand_key(k)).hex()
    assert c == "69c4e0d86a7b0430d8cdb78070b4c55a", c
    print("FIPS-197 C.1 OK:", c)
