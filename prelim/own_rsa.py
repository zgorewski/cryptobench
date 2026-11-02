"""Edukacyjna implementacja RSA (generowanie kluczy, Miller-Rabin, CRT).
Bez paddingu (textbook RSA) – tylko do wstępnych testów wydajności."""
import secrets

E = 65537


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if c % E != 1 and is_probable_prime(c):
            return c


def generate_keypair(bits: int = 2048):
    while True:
        p, q = gen_prime(bits // 2), gen_prime(bits // 2)
        if p != q and (p * q).bit_length() == bits:
            break
    n, phi = p * q, (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    return {"n": n, "e": E, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qinv": pow(q, -1, p)}


def encrypt(m: int, k) -> int:
    return pow(m, k["e"], k["n"])


def decrypt(c: int, k) -> int:  # CRT – ok. 3-4x szybciej niż pow(c, d, n)
    m1, m2 = pow(c, k["dp"], k["p"]), pow(c, k["dq"], k["q"])
    h = (k["qinv"] * (m1 - m2)) % k["p"]
    return m2 + h * k["q"]


if __name__ == "__main__":
    k = generate_keypair(1024)
    m = 123456789
    assert decrypt(encrypt(m, k), k) == m
    print("RSA round-trip OK")
