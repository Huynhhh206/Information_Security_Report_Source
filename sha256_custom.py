"""
SHA-256 tự cài đặt theo FIPS 180-4.
Chỉ dùng thư viện chuẩn để đọc dữ liệu/thời gian; không dùng hashlib để tính digest.
"""
import struct
import time

K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]
H0 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
MASK = 0xffffffff

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK

def sha256(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    msg = bytearray(data)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bit_len)

    h = H0[:]
    for offset in range(0, len(msg), 64):
        block = msg[offset:offset + 64]
        w = list(struct.unpack(">16I", block)) + [0] * 48
        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & MASK

        a,b,c,d,e,f,g,hh = h
        for i in range(64):
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) & MASK
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & MASK
            hh,g,f,e,d,c,b,a = g,f,e,(d+t1)&MASK,c,b,a,(t1+t2)&MASK
        h = [(x+y) & MASK for x,y in zip(h, [a,b,c,d,e,f,g,hh])]
    return "".join(f"{x:08x}" for x in h)

def self_test():
    vectors = {
        "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "hello": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        # Vector hai khối của NIST (thông điệp 448 bit).
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        # Họ tên dùng sinh khóa AES (khớp với ví dụ tính tay).
        "NGUYEN LUONG HUYNH":
            "4955190b027604c857aaec2d7cb6f8928999f1ea69b085c909ecb254715feee2",
    }
    for message, expected in vectors.items():
        actual = sha256(message)
        assert actual == expected, (message, actual, expected)
    print("[PASS] 5 bộ kiểm thử SHA-256")

def sha256_steps(data, max_blocks=1, max_rounds=64):
    """Chạy lại đúng quy trình của sha256() nhưng in ra từng bước trung gian.

    max_blocks: số khối 512 bit được in chi tiết (các khối sau vẫn được tính nhưng không in).
    max_rounds: số vòng nén (trên 64 vòng) được in chi tiết ở mỗi khối.
    Trả về chuỗi hex 64 ký tự, đã đối chiếu với sha256().
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    bit_len = len(data) * 8

    # ---- Bước 1: đệm dữ liệu ----
    zeros = (448 - (bit_len + 1)) % 512
    print("--- Bước 1. Đệm dữ liệu ---")
    print(f"Độ dài ban đầu l = {len(data)} byte = {bit_len} bit")
    print(f"Thêm bit 1, rồi K bit 0 sao cho l + 1 + K ≡ 448 (mod 512): K = {zeros}")
    print(f"Thêm 64 bit ghi độ dài: l = {bit_len} = 0x{bit_len:X}")
    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bit_len)
    blocks = len(msg) // 64
    print(f"Tổng: {bit_len} + 1 + {zeros} + 64 = {len(msg) * 8} bit = {blocks} khối 512 bit")
    if blocks > max_blocks:
        print(f"(Chỉ in chi tiết {max_blocks} khối đầu, các khối còn lại vẫn được tính đầy đủ.)")

    h = H0[:]
    names = "abcdefgh"
    for bi in range(blocks):
        detail = bi < max_blocks
        block = msg[bi * 64:(bi + 1) * 64]
        w = list(struct.unpack(">16I", block)) + [0] * 48
        if detail:
            print(f"\n==================== KHỐI {bi + 1}/{blocks} ====================")
            print("--- Bước 2. Chia khối thành 16 từ 32 bit W0..W15 ---")
            for i in range(0, 16, 4):
                print("  " + "   ".join(f"W{j:<2}= {w[j]:08X}" for j in range(i, i + 4)))
            print("--- Bước 3. Mở rộng thành 64 từ: Wt = σ1(Wt-2) + Wt-7 + σ0(Wt-15) + Wt-16 ---")
        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & MASK
            if detail:
                print(f"  W{i:<2}= σ1={s1:08X} + W{i-7}={w[i-7]:08X} + σ0={s0:08X} "
                      f"+ W{i-16}={w[i-16]:08X}  ->  {w[i]:08X}")

        if detail:
            print("--- Bước 4. Giá trị khởi tạo của 8 biến (a..h) ---")
            print("  " + " ".join(f"{n}={v:08X}" for n, v in zip(names, h)))
            print(f"--- Bước 5. {max_rounds} vòng nén đầu tiên (trên tổng 64 vòng) ---")
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) & MASK
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & MASK
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
            if detail and i < max_rounds:
                print(f"Vòng {i}:")
                print(f"  Σ1(e)={S1:08X} Ch={ch:08X} K{i}={K[i]:08X} W{i}={w[i]:08X}  "
                      f"->  T1=h+Σ1+Ch+K+W={t1:08X}")
                print(f"  Σ0(a)={S0:08X} Maj={maj:08X}  ->  T2=Σ0+Maj={t2:08X}")
                print("  " + " ".join(f"{n}={v:08X}" for n, v in zip(names, [a, b, c, d, e, f, g, hh])))
        old = h
        h = [(x + y) & MASK for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
        if detail:
            print("--- Bước 6. Cộng 8 biến sau 64 vòng vào giá trị băm (mod 2^32) ---")
            for n, o, v, r in zip(names, old, [a, b, c, d, e, f, g, hh], h):
                print(f"  H{names.index(n)}: {o:08X} + {v:08X} = {r:08X}")

    digest = "".join(f"{x:08x}" for x in h)
    assert digest == sha256(data), "Phần in từng bước cho kết quả khác với sha256()"
    print("\n--- Kết quả: ghép 8 giá trị băm thành 256 bit ---")
    print("SHA-256:", digest)
    return digest


def benchmark(rounds=1000):
    data = b"Cryptography experiment" * 10
    start = time.perf_counter()
    for _ in range(rounds):
        sha256(data)
    elapsed = time.perf_counter() - start
    print(f"Đo tốc độ: {rounds} lần băm, {elapsed:.6f} giây, "
          f"{elapsed/rounds*1000:.4f} ms/lần")


def read_choice(prompt, valid):
    """Hỏi đến khi người dùng nhập một lựa chọn hợp lệ."""
    while True:
        value = input(prompt).strip()
        if value in valid:
            return value
        print("  Lựa chọn không hợp lệ, hãy nhập lại.")


def ask_yes_no(prompt):
    return input(prompt).strip().lower() in ("y", "yes", "c", "co", "có")


def read_positive(prompt, default):
    """Đọc số nguyên dương; bấm Enter thì lấy giá trị mặc định."""
    while True:
        raw = input(prompt).strip()
        if raw == "":
            return default
        if raw.isdigit() and int(raw) >= 1:
            return int(raw)
        print("  Hãy nhập một số nguyên dương.")


def main():
    print("=== SHA-256 FROM SCRATCH ===")
    self_test()
    preset = "NGUYEN LUONG HUYNH"
    while True:
        print("\nChọn:")
        print(f"  1. Dùng giá trị gán sẵn: \"{preset}\"")
        print("  2. Nhập chuỗi khác")
        print("  3. Đo tốc độ")
        print("  0. Thoát")
        choice = read_choice("Lựa chọn: ", ("0", "1", "2", "3"))
        if choice == "0":
            print("Tạm biệt.")
            break
        if choice == "3":
            benchmark()
            continue
        text = preset if choice == "1" else input("Nhập chuỗi cần băm: ")
        print("Chuỗi đầu vào:", repr(text))
        if ask_yes_no("Hiển thị các bước tính? (y/N): "):
            blocks = read_positive("  Số khối in chi tiết (Enter = 1): ", 1)
            rounds = read_positive("  Số vòng nén in chi tiết mỗi khối, 1-64 (Enter = 64): ", 64)
            sha256_steps(text, blocks, min(rounds, 64))
        else:
            print("SHA-256:", sha256(text))


if __name__ == "__main__":
    main()
