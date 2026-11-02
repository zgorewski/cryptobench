"""Wstępne testy przydatności: RSA vs AES (własna implementacja vs biblioteka).
Uruchom:  pip install cryptography  &&  python prelim_bench.py
Wynik: tabela w konsoli + results.json"""
import json, os, platform, statistics, time

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import own_aes, own_rsa

R = {}


def bench(fn, repeat=5):
    ts = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts)


# --- AES (biblioteka, AES-GCM) -------------------------------------------
for bits in (128, 256):
    key = AESGCM.generate_key(bit_length=bits)
    g = AESGCM(key)
    for size in (1 << 10, 1 << 20, 10 << 20):
        data, nonce = os.urandom(size), os.urandom(12)
        t = bench(lambda: g.encrypt(nonce, data, None))
        ct = g.encrypt(nonce, data, None)
        td = bench(lambda: g.decrypt(nonce, ct, None))
        R[f"lib_aes{bits}_gcm_{size}"] = {"enc_s": t, "dec_s": td, "MBps": size / t / 1e6}

# --- AES własny (AES-128-CTR, czysty Python) -----------------------------
data = os.urandom(64 << 10)
t = bench(lambda: own_aes.encrypt_ctr(data, b"k" * 16, b"n" * 8), repeat=3)
R["own_aes128_ctr_65536"] = {"enc_s": t, "MBps": len(data) / t / 1e6}

# --- RSA (biblioteka, OAEP-SHA256) ---------------------------------------
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
for bits in (1024, 2048, 3072, 4096):
    kg = bench(lambda: rsa.generate_private_key(public_exponent=65537, key_size=bits),
               repeat=5 if bits < 4096 else 3)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    msg = os.urandom(32)  # typowo: klucz AES-256 (key wrapping)
    n = 200
    te = bench(lambda: [pub.encrypt(msg, oaep) for _ in range(n)]) / n
    ct = pub.encrypt(msg, oaep)
    td = bench(lambda: [priv.decrypt(ct, oaep) for _ in range(n // 4)]) / (n // 4)
    max_pt = bits // 8 - 2 * 32 - 2
    R[f"lib_rsa{bits}"] = {"keygen_s": kg, "enc_ms": te * 1e3, "dec_ms": td * 1e3,
                           "max_plaintext_B": max_pt,
                           "MBps_dec_est": max_pt / td / 1e6}

# --- RSA własny (textbook + CRT) -----------------------------------------
for bits in (1024, 2048):
    kg = bench(lambda: own_rsa.generate_keypair(bits), repeat=3)
    k = own_rsa.generate_keypair(bits)
    m = int.from_bytes(os.urandom(bits // 8 - 1), "big")
    c = own_rsa.encrypt(m, k)
    te = bench(lambda: [own_rsa.encrypt(m, k) for _ in range(200)]) / 200
    td = bench(lambda: [own_rsa.decrypt(c, k) for _ in range(50)]) / 50
    R[f"own_rsa{bits}"] = {"keygen_s": kg, "enc_ms": te * 1e3, "dec_ms": td * 1e3}

# --- Hybryda: RSA-2048 opakowuje klucz, AES-256-GCM szyfruje 10 MB ---------
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
data = os.urandom(10 << 20)


def hybrid():
    k = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped = priv.public_key().encrypt(k, oaep)
    ct = AESGCM(k).encrypt(nonce, data, None)
    k2 = priv.decrypt(wrapped, oaep)
    AESGCM(k2).decrypt(nonce, ct, None)


R["hybrid_rsa2048_aes256gcm_10MB_roundtrip_s"] = bench(hybrid)

meta = {"python": platform.python_version(), "cryptography": cryptography.__version__,
        "cpu": platform.processor() or platform.machine(), "os": platform.platform()}
json.dump({"meta": meta, "results": R}, open("results.json", "w"), indent=2)
print(json.dumps(meta, indent=2))
for k_, v in R.items():
    print(f"{k_:45s} {v}")
