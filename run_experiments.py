"""
Thực nghiệm cho 4 thuật toán. Không dùng thư viện mật mã.
Chạy:  python run_experiments.py        (mất khoảng 1-2 phút)
Kết quả in ra màn hình và ghi vào results.json.
"""
import json
import math
import platform
import secrets
import sys
import time

import aes128 as AES
import diffie_hellman as DH
import elgamal_signature as EG
import sha256_custom as SHA
from number_theory import find_generator, generate_safe_prime, is_probable_prime

results = {}


def timed(fn, repeat=1):
    start = time.perf_counter()
    for _ in range(repeat):
        out = fn()
    return out, (time.perf_counter() - start) / repeat


def header(title):
    print("\n" + "=" * 70 + "\n" + title + "\n" + "=" * 70)


# ---------------------------------------------------------------- môi trường
header("MÔI TRƯỜNG")
env = {"python": sys.version.split()[0], "os": platform.platform(), "machine": platform.machine()}
print(env)
results["env"] = env

# ---------------------------------------------------------------- SHA-256
header("SHA-256")
vectors = [
    ("chuỗi rỗng", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("NIST 448 bit", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ("NGUYEN LUONG HUYNH", "NGUYEN LUONG HUYNH",
     "4955190b027604c857aaec2d7cb6f8928999f1ea69b085c909ecb254715feee2"),
]
sha_rows = []
for name, msg, expected in vectors:
    got = SHA.sha256(msg)
    sha_rows.append((name, got == expected))
    print(f"{name:22} {'đạt' if got == expected else 'KHÔNG ĐẠT'}  {got[:16]}...")
million, t_million = timed(lambda: SHA.sha256(b"a" * 1_000_000))
ok = million == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
sha_rows.append(("một triệu chữ a", ok))
print(f"{'một triệu chữ a':22} {'đạt' if ok else 'KHÔNG ĐẠT'}  ({t_million:.2f} s)")

base = bytearray(b"The quick brown fox jumps over the lazy dog")
h0 = int(SHA.sha256(bytes(base)), 16)
flips = []
for bit in range(len(base) * 8):
    m = bytearray(base)
    m[bit // 8] ^= 1 << (bit % 8)
    flips.append(bin(h0 ^ int(SHA.sha256(bytes(m)), 16)).count("1"))
avalanche = {"flips": len(flips), "mean_bits": sum(flips) / len(flips), "min": min(flips), "max": max(flips)}
print("Hiệu ứng thác đổ:", avalanche)

speeds = {}
for size in (64, 1024, 65536):
    data = bytes(size)
    reps = max(3, 200000 // size)
    _, t = timed(lambda: SHA.sha256(data), repeat=reps)
    speeds[size] = {"seconds": t, "mb_per_s": size / t / 1e6}
    print(f"băm {size:6d} byte: {t * 1000:8.3f} ms  ({size / t / 1e6:.3f} MB/s)")
results["sha256"] = {"vectors": sha_rows, "avalanche": avalanche, "speed": speeds, "million_a_seconds": t_million}

# ---------------------------------------------------------------- AES-128
header("AES-128")
key = AES.key_from_full_name("Nguyễn Lương Huynh")
print("Khóa từ họ tên:", key.hex())
aes_rows = []
for key_hex, plain_hex, cipher_hex in [
    ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
]:
    rk = AES.expand_key(bytes.fromhex(key_hex))
    enc = AES.encrypt_block(bytes.fromhex(plain_hex), rk).hex()
    dec = AES.decrypt_block(bytes.fromhex(cipher_hex), rk).hex()
    aes_rows.append((cipher_hex[:8], enc == cipher_hex and dec == plain_hex))
    print("vector", cipher_hex[:8], "mã hóa+giải mã:", enc == cipher_hex and dec == plain_hex)
ok_lengths = 0
lengths = list(range(0, 65)) + [1000]
for n in lengths:
    data = secrets.token_bytes(n)
    iv, ct = AES.encrypt_cbc(data, key)
    ok_lengths += AES.decrypt_cbc(iv, ct, key) == data
print(f"CBC mã hóa rồi giải mã: {ok_lengths}/{len(lengths)} độ dài đạt")
aes_speed = {}
for size in (1024, 65536):
    data = bytes(size)
    (iv, ct), te = timed(lambda: AES.encrypt_cbc(data, key))
    _, td = timed(lambda: AES.decrypt_cbc(iv, ct, key))
    aes_speed[size] = {"enc_kib_s": size / te / 1024, "dec_kib_s": size / td / 1024}
    print(f"{size:6d} byte: mã hóa {size / te / 1024:7.0f} KiB/s, giải mã {size / td / 1024:7.0f} KiB/s")
results["aes"] = {"vectors": aes_rows, "cbc_ok": ok_lengths, "cbc_total": len(lengths), "speed": aes_speed, "key": key.hex()}

# ---------------------------------------------------------------- Diffie-Hellman
header("DIFFIE-HELLMAN")
small = (23, 5, 6, 15)
p, g, a, b = small
A, B = DH.mod_pow(g, a, p), DH.mod_pow(g, b, p)
print("Ví dụ p=23, g=5, a=6, b=15: A, B, K =", A, B, DH.mod_pow(B, a, p))
equal = 0
N = 30
for _ in range(N):
    x, y = DH.generate_private_key(), DH.generate_private_key()
    equal += DH.shared_secret(DH.public_key(y), x) == DH.shared_secret(DH.public_key(x), y)
print(f"Nhóm 2048-bit: {equal}/{N} lần hai bên ra cùng khóa chung")
start = time.perf_counter()
p_prime = is_probable_prime(DH.P_2048, trial=False)
q_prime = is_probable_prime(DH.Q if DH.P is DH.P_2048 else (DH.P_2048 - 1) // 2, trial=False)
t_mr = time.perf_counter() - start
print(f"Miller-Rabin tự cài: p 2048-bit nguyên tố = {p_prime}, (p-1)/2 nguyên tố = {q_prime} ({t_mr:.2f} s)")
subgroup = (DH.mod_pow(2, DH.Q, DH.P_2048) == 1)
print("g = 2 có bậc q (2^q = 1 mod p):", subgroup)

# thời gian theo cỡ p
dh_time = []
groups = {}
for bits in (256, 512):
    (pp, qq), t_gen = timed(lambda: generate_safe_prime(bits))
    groups[bits] = (pp, find_generator(pp, qq), t_gen)
groups[1536] = (DH.P_1536, 2, None)
groups[2048] = (DH.P_2048, 2, None)
for bits in (256, 512, 1536, 2048):
    pp, gg, t_gen = groups[bits]
    reps = 20 if bits <= 512 else 5

    def exchange():
        x = secrets.randbelow(pp - 3) + 2
        y = secrets.randbelow(pp - 3) + 2
        X, Y = DH.mod_pow(gg, x, pp), DH.mod_pow(gg, y, pp)
        assert DH.mod_pow(Y, x, pp) == DH.mod_pow(X, y, pp)

    _, t = timed(exchange, repeat=reps)
    row = {"bits": bits, "exchange_ms": t * 1000, "gen_seconds": t_gen}
    dh_time.append(row)
    print(f"p {bits:4d} bit: một lần trao đổi đủ 4 phép lũy thừa {t * 1000:8.2f} ms"
          + (f", sinh số nguyên tố an toàn {t_gen:.2f} s" if t_gen else ""))

# dò khóa bí mật bằng vét cạn
brute = []
for bits in (16, 20, 24, 28):
    pp, qq = generate_safe_prime(bits)
    gg = find_generator(pp, qq)
    secret = pp // 2                       # đặt bí mật ở giữa khoảng để so sánh công bằng
    target = DH.mod_pow(gg, secret, pp)
    start = time.perf_counter()
    value, tries = 1, 0
    while True:
        tries += 1
        value = (value * gg) % pp
        if value == target:
            break
    t = time.perf_counter() - start
    brute.append({"bits": bits, "p": pp, "tries": tries, "seconds": t, "found": True})
    print(f"vét cạn p {bits} bit (p={pp}): {tries} lần thử, {t:.3f} s")

# tấn công xen giữa
a_s, b_s, m_s = (DH.generate_private_key() for _ in range(3))
A_, B_, M_ = DH.public_key(a_s), DH.public_key(b_s), DH.public_key(m_s)
k_alice = DH.shared_secret(M_, a_s)            # Alice tưởng M là Bob
k_bob = DH.shared_secret(M_, b_s)              # Bob tưởng M là Alice
mitm = {"alice_eq_mallory": k_alice == DH.shared_secret(A_, m_s),
        "bob_eq_mallory": k_bob == DH.shared_secret(B_, m_s),
        "alice_eq_bob": k_alice == k_bob}
print("Tấn công xen giữa (không có xác thực):", mitm)
results["dh"] = {"safe_prime_check": [p_prime, q_prime, t_mr], "g_order_q": subgroup, "time": dh_time, "brute": brute, "mitm": mitm, "same_key": (equal, N)}

# ---------------------------------------------------------------- ElGamal
header("ELGAMAL")
assert EG.sign_hash(7, 6, 23, 5, k=5) == (20, 17)
print("Ví dụ tay p=23, g=5, x=6, k=5, H=7 -> chữ ký (20, 17): đạt")
good = bad_detect = 0
M = 200
for i in range(M):
    x, y = EG.generate_keys(DH.P_2048, 2)
    msg = f"thong diep {i}"
    sig = EG.sign(msg, x, DH.P_2048, 2)
    good += EG.verify(msg, sig, y, DH.P_2048, 2)
    bad_detect += not EG.verify(msg + "!", sig, y, DH.P_2048, 2)
print(f"Nhóm 2048-bit: {good}/{M} chữ ký đúng được chấp nhận, {bad_detect}/{M} thông điệp bị sửa bị từ chối")

# nhóm nhỏ: tỉ lệ thông điệp sửa vẫn qua mặt vì h trùng
T = 20000
miss = 0
for i in range(T):
    x, y = EG.generate_keys()
    msg = f"msg{i}"
    sig = EG.sign(msg, x)
    miss += EG.verify(msg + "!", sig, y)
print(f"Nhóm p=467: {miss}/{T} thông điệp bị sửa vẫn được chấp nhận ({miss / T * 100:.2f}%) vì h chỉ có 9 bit")

# tốc độ theo cỡ p
eg_time = []
for bits in (256, 512, 2048):
    if bits == 2048:
        pp, gg = DH.P_2048, 2
    else:
        pp, gg, _ = groups[bits]
    x, y = EG.generate_keys(pp, gg)
    _, ts = timed(lambda: EG.sign("thong diep", x, pp, gg), repeat=10)
    sig = EG.sign("thong diep", x, pp, gg)
    _, tv = timed(lambda: EG.verify("thong diep", sig, y, pp, gg), repeat=10)
    eg_time.append({"bits": bits, "sign_ms": ts * 1000, "verify_ms": tv * 1000, "sig_bits": 2 * bits})
    print(f"p {bits:4d} bit: ký {ts * 1000:8.2f} ms, kiểm tra {tv * 1000:8.2f} ms, chữ ký ~{2 * bits} bit")

# dùng lại k làm lộ khóa bí mật (nhóm nhỏ)
P_, G_ = EG.SMALL_P, EG.SMALL_G
x_secret = secrets.randbelow(P_ - 2) + 1
k_fixed = next(k for k in range(2, P_ - 1) if math.gcd(k, P_ - 1) == 1 and math.gcd(pow(G_, k, P_), P_ - 1) == 1)
m1, m2 = "thanh toan 10", "thanh toan 99"
h1, h2 = EG.hash_to_int(m1, P_), EG.hash_to_int(m2, P_)
r1, s1 = EG.sign_hash(h1, x_secret, P_, G_, k=k_fixed)
r2, s2 = EG.sign_hash(h2, x_secret, P_, G_, k=k_fixed)
d = (s1 - s2) % (P_ - 1)
g_ = math.gcd(d, P_ - 1)
recovered = []
if (h1 - h2) % g_ == 0:
    mod = (P_ - 1) // g_
    k0 = (((h1 - h2) // g_) * EG.mod_inverse(d // g_, mod)) % mod
    for j in range(g_):
        kk = k0 + j * mod
        if pow(G_, kk, P_) == r1:
            recovered.append((EG.mod_inverse(r1, P_ - 1) * (h1 - s1 * kk)) % (P_ - 1))
reuse = {"true_x": x_secret, "recovered": recovered, "success": x_secret in recovered}
print("Dùng lại k (p=467):", reuse)
results["elgamal"] = {"time": eg_time, "good": (good, M), "detected": (bad_detect, M), "small_miss": (miss, T), "reuse": reuse}

with open("results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=1)
print("\nĐã ghi results.json")
