"""
ELGAMAL DIGITAL SIGNATURE tự cài đặt.

- SHA-256: dùng sha256_custom.py (tự cài), không dùng hashlib.
- Lũy thừa modular: dùng mod_pow trong diffie_hellman.py (tự cài).
- Nghịch đảo modular: extended_gcd viết dạng vòng lặp (không đệ quy) để chạy được với p 2048-bit.
- Nhóm nhỏ p = 467, g = 2: để kiểm tay, KHÔNG an toàn.
- Nhóm lớn: RFC 3526 group 14 (2048-bit), g = 2.

Chạy:
    python elgamal_signature.py
"""
import secrets
from math import gcd

from sha256_custom import sha256
from diffie_hellman import P as BIG_P, G as BIG_G, mod_pow, read_int, read_prime, read_choice

SMALL_P, SMALL_G = 467, 2


def extended_gcd(a, b):
    """Trả về (d, x, y) sao cho a*x + b*y = d = gcd(a, b). Viết bằng vòng lặp."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def mod_inverse(a, modulus):
    """Nghịch đảo của a modulo `modulus`; báo lỗi nếu gcd khác 1."""
    d, x, _ = extended_gcd(a % modulus, modulus)
    if d != 1:
        raise ValueError("Không tồn tại nghịch đảo modulo.")
    return x % modulus


def hash_to_int(message, p):
    """h = SHA-256(message) rút gọn modulo (p - 1)."""
    return int(sha256(message), 16) % (p - 1)


def generate_keys(p=SMALL_P, g=SMALL_G):
    """x: khóa bí mật, 1 <= x <= p-2. y = g^x mod p: khóa công khai."""
    private_key = secrets.randbelow(p - 2) + 1
    return private_key, mod_pow(g, private_key, p)


def _sign_with_k(h, private_key, p, g, k):
    r = mod_pow(g, k, p)
    s = (mod_inverse(k, p - 1) * (h - private_key * r)) % (p - 1)
    return r, s


def sign_hash(h, private_key, p=SMALL_P, g=SMALL_G, k=None):
    """Ký giá trị băm h (số nguyên). Nếu không truyền k thì chọn k ngẫu nhiên.

    k phải nguyên tố cùng nhau với p-1. Nếu s = 0 thì chọn lại k, vì s = 0 có thể làm lộ khóa bí mật.
    """
    if k is not None:
        if gcd(k, p - 1) != 1:
            raise ValueError("k phải nguyên tố cùng nhau với p-1")
        r, s = _sign_with_k(h, private_key, p, g, k)
        if s == 0:
            raise ValueError("s = 0, hãy chọn k khác")
        return r, s
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) != 1:
            continue
        r, s = _sign_with_k(h, private_key, p, g, k)
        if s != 0:
            return r, s


def verify_hash(h, signature, public_key, p=SMALL_P, g=SMALL_G):
    """Kiểm tra: 0 < r < p, 0 < s < p-1 và g^h = y^r * r^s (mod p)."""
    r, s = signature
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False
    left = mod_pow(g, h, p)
    right = (mod_pow(public_key, r, p) * mod_pow(r, s, p)) % p
    return left == right


def sign(message, private_key, p=SMALL_P, g=SMALL_G):
    return sign_hash(hash_to_int(message, p), private_key, p, g)


def verify(message, signature, public_key, p=SMALL_P, g=SMALL_G):
    return verify_hash(hash_to_int(message, p), signature, public_key, p, g)


def self_test():
    # Ví dụ tính tay: p=23, g=5, x=6, k=5, H=7 cho chữ ký (20, 17).
    assert mod_inverse(5, 22) == 9 and mod_inverse(7, 23) == 10
    assert mod_pow(5, 6, 23) == 8
    assert sign_hash(7, 6, 23, 5, k=5) == (20, 17)
    assert verify_hash(7, (20, 17), 8, 23, 5)
    assert not verify_hash(8, (20, 17), 8, 23, 5)          # H bị đổi thành 8
    # Nhóm nhỏ p=467: chữ ký đúng luôn được chấp nhận; r, s ngoài miền bị từ chối.
    for i in range(300):
        x, y = generate_keys()
        sig = sign(f"thong diep {i}", x)
        assert verify(f"thong diep {i}", sig, y)
        assert sig[1] != 0
    assert not verify("a", (0, 5), 8) and not verify("a", (5, 0), 8)
    # Nhóm 2048-bit: ký, kiểm tra, và phát hiện thông điệp bị sửa.
    x, y = generate_keys(BIG_P, BIG_G)
    message = "Xin chao, day la thong diep can ky"
    sig = sign(message, x, BIG_P, BIG_G)
    assert verify(message, sig, y, BIG_P, BIG_G)
    assert not verify(message + "!", sig, y, BIG_P, BIG_G)
    print("[PASS] Ví dụ tay (20, 17), nhóm p=467, nhóm 2048-bit")


def show(n):
    """Số nhỏ in đầy đủ; số lớn chỉ in 16 chữ số hex đầu."""
    return str(n) if n.bit_length() <= 64 else format(n, "x")[:16] + "... (hex, rút gọn)"


def ask_group():
    """Nhập p (phải là số nguyên tố) và g."""
    p = read_prime("Nhập số nguyên tố p (Enter = nhóm 2048-bit RFC 3526; ví dụ 467 hoặc 23): ",
                   minimum=5, allow_blank=True)
    if p is None:
        return BIG_P, BIG_G
    g = read_int(f"Nhập phần tử sinh g (2 <= g <= {p - 2}): ", 2, p - 2)
    return p, g


def ask_data(p):
    """Trả về (chế độ, thông điệp hoặc None, giá trị băm h)."""
    print("Chọn dữ liệu cần ký:")
    print("  1. Thông điệp văn bản (băm bằng SHA-256 rồi rút gọn modulo p-1)")
    print("  2. Nhập trực tiếp giá trị băm H (số nguyên)")
    mode = read_choice("Chọn 1 hoặc 2: ", ("1", "2"))
    if mode == "1":
        message = input("Nhập thông điệp cần ký: ")
        return mode, message, hash_to_int(message, p)
    return mode, None, read_int("Nhập giá trị băm H (H >= 0): ", minimum=0)


def ask_k(p):
    return read_int(f"Số ngẫu nhiên k (1 <= k <= {p - 2}, nguyên tố cùng nhau với p-1, "
                    "Enter = chọn ngẫu nhiên): ", 1, p - 2, allow_blank=True)


def sign_with_prompt(h, x, p, g, k):
    """Ký; nếu k không hợp lệ thì hỏi lại k."""
    while True:
        try:
            return sign_hash(h, x, p, g, k=k)
        except ValueError as error:
            print("  [LỖI]", error, "- hãy nhập lại.")
            k = ask_k(p)


def report(p, g, x, y, mode, message, h, signature):
    r, s = signature
    valid_original = verify_hash(h, signature, y, p, g)
    # Dữ liệu bị sửa, GIỮ NGUYÊN chữ ký cũ.
    if mode == "1":
        tampered = message + "!"
        while hash_to_int(tampered, p) == h:      # p quá nhỏ có thể làm h trùng, thì thêm "!" tiếp
            tampered += "!"
        h_tampered = hash_to_int(tampered, p)
    else:
        tampered = None
        h_tampered = h + 1
    valid_tampered = verify_hash(h_tampered, signature, y, p, g)

    print("\n--- KẾT QUẢ ---")
    if mode == "1":
        print("Thông điệp gốc:", repr(message))
        print("SHA-256 thông điệp gốc:", sha256(message))
    print("H =", show(h))
    print("Khóa bí mật x =", show(x))
    print("Khóa công khai y = g^x mod p =", show(y))
    print("Chữ ký r = g^k mod p =", show(r))
    print("Chữ ký s = k^(-1)(H - x*r) mod (p-1) =", show(s))
    left = mod_pow(g, h, p)
    right = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
    print("Kiểm tra: g^H mod p =", show(left), "| y^r * r^s mod p =", show(right))
    print("Kiểm tra dữ liệu gốc:", valid_original)
    if mode == "1":
        print("Thông điệp bị sửa:", repr(tampered))
    print("Giá trị băm bị sửa H' =", show(h_tampered))
    print("Kiểm tra dữ liệu bị sửa bằng CHỮ KÝ CŨ:", valid_tampered)
    if valid_original and not valid_tampered:
        print("\n[PASS] ElGamal phát hiện được dữ liệu bị thay đổi.")
    elif valid_original:
        print("\n[LƯU Ý] Dữ liệu bị sửa vẫn qua kiểm tra (xảy ra với p nhỏ hoặc tham số không an toàn).")
    else:
        print("\n[FAIL] Có vấn đề trong quá trình ký hoặc xác minh.")


def main():
    print("=== ELGAMAL DIGITAL SIGNATURE ===")
    self_test()
    while True:
        print("\nChọn:")
        print("  1. Dùng giá trị gán sẵn (ví dụ tay): p = 23, g = 5, x = 6, H = 7, k = 5")
        print("  2. Nhập giá trị khác")
        print("  0. Thoát")
        choice = read_choice("Lựa chọn: ", ("0", "1", "2"))
        if choice == "0":
            print("Tạm biệt.")
            break
        if choice == "1":
            p, g, x, mode, message, h, k = 23, 5, 6, "2", None, 7, 5
            y = mod_pow(g, x, p)
        else:
            p, g = ask_group()
            print("Nhóm đang dùng: p có", p.bit_length(), "bit, g =", g)
            x = read_int(f"Khóa bí mật x (1 <= x <= {p - 2}, Enter = chọn ngẫu nhiên): ",
                         1, p - 2, allow_blank=True)
            if x is None:
                x, y = generate_keys(p, g)
            else:
                y = mod_pow(g, x, p)
            mode, message, h = ask_data(p)
            k = ask_k(p)
        while True:
            signature = sign_with_prompt(h, x, p, g, k)
            report(p, g, x, y, mode, message, h, signature)
            again = input("\nKý lại cùng dữ liệu với k khác (giữ nguyên p, g, x)? (y/N): ")
            if again.strip().lower() not in ("y", "yes", "c", "co", "có"):
                break
            k = ask_k(p)


if __name__ == "__main__":
    main()
