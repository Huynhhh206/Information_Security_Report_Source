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
from diffie_hellman import (P as BIG_P, G as BIG_G, mod_pow, read_int, read_prime, read_choice,
                            ask_yes_no, mod_pow_steps, show_number)
from number_theory import is_probable_prime
from test_log import log_result

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


def show(n, full=False):
    """Số nhỏ in đầy đủ; số lớn chỉ in đầu và cuối (dùng chung cách in với diffie_hellman.py)."""
    return show_number(n, full)


def mod_inverse_steps(a, modulus, full=False):
    """Tìm nghịch đảo của a modulo `modulus` bằng Euclid mở rộng và in từng bước (giống cách tính tay)."""
    a %= modulus
    print(f"k^(-1): nghịch đảo của {show(a, full)} modulo {show(modulus, full)} (Euclid mở rộng)")
    old_r, r = modulus, a
    old_s, s_ = 1, 0          # hệ số của modulus
    old_t, t_ = 0, 1          # hệ số của a
    print("  Chia liên tiếp:")
    count = 0
    while r != 0:
        q = old_r // r
        count += 1
        if count <= 12 or r == 0:
            print(f"    {show(old_r, full)} = {show(q, full)} · {show(r, full)} + {show(old_r - q * r, full)}")
        elif count == 13:
            print("    ...")
        old_r, r = r, old_r - q * r
        old_s, s_ = s_, old_s - q * s_
        old_t, t_ = t_, old_t - q * t_
    if old_r != 1:
        raise ValueError(f"gcd = {old_r}, không có nghịch đảo")
    inverse = old_t % modulus
    print(f"  Sau {count} phép chia: gcd = 1 = ({show(old_s, full)})·{show(modulus, full)} + ({show(old_t, full)})·{show(a, full)}")
    print(f"  => k^(-1) = {show(old_t, full)} mod {show(modulus, full)} = {show(inverse, full)}")
    assert inverse == mod_inverse(a, modulus)
    return inverse


def choose_k(p):
    """Chọn k ngẫu nhiên nguyên tố cùng nhau với p - 1."""
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            return k


def check_group(p, g, x=None):
    """Kiểm tra tham số (dùng cho chạy hàng loạt); sai thì báo ValueError."""
    if p < 5:
        raise ValueError("p phải từ 5 trở lên")
    if not is_probable_prime(p):
        raise ValueError(f"{p} không phải số nguyên tố (Miller-Rabin)")
    if not 2 <= g <= p - 2:
        raise ValueError(f"g phải trong khoảng 2 đến {p - 2}")
    if x is not None and not 1 <= x <= p - 2:
        raise ValueError(f"Khóa bí mật x phải trong khoảng 1 đến {p - 2}")


def sign_report(p, g, x, k, h, h_tampered=None):
    """Ký giá trị băm h bằng p, g, x, k (k = None: ngẫu nhiên) và kiểm tra, không in gì (chạy hàng loạt)."""
    check_group(p, g, x)
    if h < 0:
        raise ValueError("H không được âm")
    if k is not None:
        if not 1 <= k <= p - 2:
            raise ValueError(f"k phải trong khoảng 1 đến {p - 2}")
        if gcd(k, p - 1) != 1:
            raise ValueError(f"k phải nguyên tố cùng nhau với p - 1 = {p - 1}, nhưng gcd(k, p - 1) = {gcd(k, p - 1)}")
    y = mod_pow(g, x, p)
    r, s = sign_hash(h, x, p, g, k)
    left = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
    report_ = {"y": y, "r": r, "s": s, "left": left, "right": mod_pow(g, h, p),
               "valid": verify_hash(h, (r, s), y, p, g)}
    if h_tampered is not None:
        report_["right_tampered"] = mod_pow(g, h_tampered, p)
        report_["valid_tampered"] = verify_hash(h_tampered, (r, s), y, p, g)
        report_["identical"] = h_tampered == h
    return report_


def message_report(message, tampered=None, big=False, x=None, k=None):
    """Ký một thông điệp (nhóm nhỏ p = 467 hoặc nhóm 2048-bit), kiểm tra bản gốc và bản bị sửa."""
    p, g = (BIG_P, BIG_G) if big else (SMALL_P, SMALL_G)
    if x is None:
        x, y = generate_keys(p, g)
    else:
        check_group(p, g, x)
        y = mod_pow(g, x, p)
    h = hash_to_int(message, p)
    if k is not None and gcd(k, p - 1) != 1:
        raise ValueError(f"k phải nguyên tố cùng nhau với p - 1 = {p - 1}")
    r, s = sign_hash(h, x, p, g, k)
    report_ = {"p": p, "g": g, "x": x, "y": y, "h": h, "r": r, "s": s, "valid": verify_hash(h, (r, s), y, p, g)}
    if tampered is not None:
        h2 = hash_to_int(tampered, p)
        report_.update({"h_tampered": h2, "identical": tampered == message, "collision": h2 == h and tampered != message,
                        "valid_tampered": verify_hash(h2, (r, s), y, p, g)})
    return report_


def verify_report(p, g, y, h, r, s):
    """Kiểm tra một chữ ký nhập tay (r, s), không in gì (chạy hàng loạt)."""
    check_group(p, g)
    in_range = 0 < r < p and 0 < s < p - 1
    left = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p if in_range else None
    return {"in_range": in_range, "left": left, "right": mod_pow(g, h, p),
            "valid": verify_hash(h, (r, s), y, p, g)}


def ask_group():
    """Nhập p (phải là số nguyên tố) và g."""
    p = read_prime("Nhập số nguyên tố p (Enter = nhóm 2048-bit RFC 3526; ví dụ 467 hoặc 23): ",
                   minimum=5, allow_blank=True)
    if p is None:
        return BIG_P, BIG_G
    g = read_int(f"Nhập phần tử sinh g (2 <= g <= {p - 2}): ", 2, p - 2)
    return p, g


def ask_data(p, verb="ký"):
    """Trả về (chế độ, thông điệp hoặc None, giá trị băm h)."""
    print(f"Chọn dữ liệu cần {verb}:")
    print("  1. Thông điệp văn bản (băm bằng SHA-256 rồi rút gọn modulo p-1)")
    print("  2. Nhập trực tiếp giá trị băm H (số nguyên)")
    mode = read_choice("Chọn 1 hoặc 2: ", ("1", "2"))
    if mode == "1":
        message = input(f"Nhập thông điệp cần {verb}: ")
        return mode, message, hash_to_int(message, p)
    return mode, None, read_int("Nhập giá trị băm H (H >= 0): ", minimum=0)


def ask_k(p):
    return read_int(f"Số ngẫu nhiên k (1 <= k <= {p - 2}, nguyên tố cùng nhau với p-1, "
                    "Enter = chọn ngẫu nhiên): ", 1, p - 2, allow_blank=True)


def ask_tampered(mode):
    """Dữ liệu sau khi bị sửa, do bạn nhập. Enter = tự sửa (thêm dấu ! hoặc H + 1)."""
    if mode == "1":
        text = input("Nhập thông điệp bị sửa (Enter = tự thêm dấu !): ")
        return text if text != "" else None
    return read_int("Nhập H' sau khi bị sửa (Enter = H + 1): ", minimum=0, allow_blank=True)


def sign_with_prompt(h, x, p, g, k):
    """Ký; nếu k không hợp lệ thì hỏi lại k. Trả về (r, s, k đã dùng)."""
    while True:
        try:
            if k is None:
                for _ in range(1000):                       # k ngẫu nhiên; s = 0 thì chọn lại
                    k_try = choose_k(p)
                    try:
                        r, s = sign_hash(h, x, p, g, k=k_try)
                        return r, s, k_try
                    except ValueError:
                        continue
                raise ValueError("Không tìm được k phù hợp với các tham số này")
            r, s = sign_hash(h, x, p, g, k=k)
            return r, s, k
        except ValueError as error:
            print("  [LỖI]", error, "- hãy nhập lại.")
            k = ask_k(p)


def report(p, g, x, y, mode, message, h, signature, k, tampered_input=None, steps=False, full=False):
    """In kết quả ký và kiểm tra. Trả về dict tóm tắt để ghi lại."""
    r, s = signature
    valid_original = verify_hash(h, signature, y, p, g)
    # Dữ liệu bị sửa, GIỮ NGUYÊN chữ ký cũ.
    if mode == "1":
        tampered = tampered_input if tampered_input is not None else message + "!"
        if tampered_input is None:
            while hash_to_int(tampered, p) == h:      # p quá nhỏ có thể làm h trùng, thì thêm "!" tiếp
                tampered += "!"
        h_tampered = hash_to_int(tampered, p)
        identical = tampered == message
    else:
        tampered = None
        h_tampered = tampered_input if tampered_input is not None else h + 1
        identical = h_tampered == h
    valid_tampered = verify_hash(h_tampered, signature, y, p, g)

    if steps:
        print("\n--- CÁC BƯỚC TÍNH ---")
        mod_pow_steps(g, x, p, "y = g^x mod p", full)
        mod_pow_steps(g, k, p, "r = g^k mod p", full)
        k_inv = mod_inverse_steps(k, p - 1, full)
        print("s = k^(-1)·(H - x·r) mod (p-1)")
        if p.bit_length() <= 64:
            print(f"  H - x·r = {h} - {x}·{r} = {h - x * r}")
            print(f"  s = {k_inv} · ({h - x * r}) mod {p - 1} = {s}")
        else:
            print(f"  s = {show(s, full)}")
        print("Kiểm tra chữ ký: cần g^H mod p = y^r · r^s mod p")
        mod_pow_steps(g, h, p, "g^H mod p", full)
        mod_pow_steps(y, r, p, "y^r mod p", full)
        mod_pow_steps(r, s, p, "r^s mod p", full)

    print("\n--- KẾT QUẢ ---")
    if mode == "1":
        print("Thông điệp gốc:", repr(message))
        print("SHA-256 thông điệp gốc:", sha256(message))
    print("H =", show(h, full))
    print("Khóa bí mật x =", show(x, full))
    print("Khóa công khai y = g^x mod p =", show(y, full))
    print("Số ngẫu nhiên k =", show(k, full))
    print("Chữ ký r = g^k mod p =", show(r, full))
    print("Chữ ký s = k^(-1)(H - x*r) mod (p-1) =", show(s, full))
    left = mod_pow(g, h, p)
    right = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
    print("Kiểm tra: g^H mod p =", show(left, full), "| y^r * r^s mod p =", show(right, full))
    print("Kiểm tra dữ liệu gốc:", valid_original)
    if mode == "1":
        print("Thông điệp bị sửa:", repr(tampered))
    print("Giá trị băm bị sửa H' =", show(h_tampered, full))
    if identical:
        print("(Dữ liệu 'bị sửa' giống hệt dữ liệu gốc nên chữ ký vẫn hợp lệ là đúng.)")
    print("Kiểm tra dữ liệu bị sửa bằng CHỮ KÝ CŨ:", valid_tampered)
    expected_tampered = valid_tampered if identical else not valid_tampered
    if valid_original and expected_tampered and not identical:
        print("\n[PASS] ElGamal phát hiện được dữ liệu bị thay đổi.")
    elif valid_original and identical:
        print("\n[PASS] Chữ ký đúng với dữ liệu gốc.")
    elif valid_original:
        print("\n[LƯU Ý] Dữ liệu bị sửa vẫn qua kiểm tra (xảy ra với p nhỏ: h chỉ có vài bit nên có thể trùng).")
    else:
        print("\n[FAIL] Có vấn đề trong quá trình ký hoặc xác minh.")
    return {"left": left, "right": right, "valid": valid_original, "valid_tampered": valid_tampered,
            "tampered": tampered, "h_tampered": h_tampered, "identical": identical,
            "ok": valid_original and expected_tampered}


def verify_manual():
    """Kiểm tra một chữ ký (r, s) do bạn nhập, với p, g, khóa công khai y và dữ liệu (thông điệp hoặc H)."""
    p, g = ask_group()
    y = read_int(f"Khóa công khai y (1 <= y <= {p - 1}): ", 1, p - 1)
    mode, message, h = ask_data(p, "kiểm tra")
    r = read_int("Chữ ký r (số nguyên >= 0): ", minimum=0)
    s = read_int("Chữ ký s (số nguyên >= 0): ", minimum=0)
    steps = ask_yes_no("Hiển thị các bước tính? (y/N): ")
    full = ask_yes_no("In đầy đủ các số lớn? (y/N, mặc định rút gọn): ") if p.bit_length() > 64 else False
    in_range = 0 < r < p and 0 < s < p - 1
    print("\n--- KẾT QUẢ ---")
    if mode == "1":
        print("Thông điệp:", repr(message))
    print("H =", show(h, full))
    if not in_range:
        print(f"Chữ ký bị từ chối vì r, s phải thỏa 0 < r < p và 0 < s < p - 1 (r = {show(r, full)}, s = {show(s, full)}).")
        valid, left = False, None
    else:
        if steps:
            print("--- CÁC BƯỚC TÍNH ---")
            mod_pow_steps(g, h, p, "g^H mod p", full)
            mod_pow_steps(y, r, p, "y^r mod p", full)
            mod_pow_steps(r, s, p, "r^s mod p", full)
        right = mod_pow(g, h, p)
        left = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p
        print("Vế trái  y^r * r^s mod p =", show(left, full))
        print("Vế phải  g^H mod p       =", show(right, full))
        valid = verify_hash(h, (r, s), y, p, g)
    print("Chữ ký hợp lệ:", valid)
    n = log_result("ElGamal kiểm tra chữ ký",
                   f"p={show(p)}, g={g}, y={show(y)}, " + (f"thông điệp={message!r}" if mode == "1" else f"H={show(h)}")
                   + f", (r,s)=({show(r)},{show(s)})",
                   f"VT={show(left) if left is not None else 'ngoài miền'}, VP={show(mod_pow(g, h, p))}, hợp lệ={valid}",
                   None)
    print(f"(đã ghi lần thử số {n} vào ket_qua_test.csv)")


def main():
    print("=== ELGAMAL DIGITAL SIGNATURE ===")
    self_test()
    while True:
        print("\nChọn:")
        print("  1. Dùng giá trị gán sẵn (ví dụ tay): p = 23, g = 5, x = 6, H = 7, k = 5")
        print("  2. Nhập giá trị khác để ký")
        print("  3. Kiểm tra một chữ ký (r, s) do bạn nhập")
        print("  0. Thoát")
        choice = read_choice("Lựa chọn: ", ("0", "1", "2", "3"))
        if choice == "0":
            print("Tạm biệt.")
            break
        if choice == "3":
            verify_manual()
            continue
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
        tampered_input = ask_tampered(mode)
        steps = ask_yes_no("Hiển thị các bước tính? (y/N): ")
        full = ask_yes_no("In đầy đủ các số lớn? (y/N, mặc định rút gọn): ") if p.bit_length() > 64 else False
        while True:
            r, s, k_used = sign_with_prompt(h, x, p, g, k)
            result = report(p, g, x, y, mode, message, h, (r, s), k_used, tampered_input, steps, full)
            data = f"thông điệp={message!r}" if mode == "1" else f"H={show(h)}"
            fixed = f"sửa={result['tampered']!r}" if mode == "1" else f"H'={show(result['h_tampered'])}"
            n = log_result("ElGamal ký",
                           f"p={show(p)}, g={g}, x={show(x)}, k={show(k_used)}, {data}, {fixed}",
                           f"y={show(y)}, (r,s)=({show(r)},{show(s)}), VT={show(result['right'])}, VP={show(result['left'])}, "
                           f"hợp lệ={result['valid']}, bản sửa hợp lệ={result['valid_tampered']}", result["ok"])
            print(f"(đã ghi lần thử số {n} vào ket_qua_test.csv)")
            again = input("\nKý lại cùng dữ liệu với k khác (giữ nguyên p, g, x)? (y/N): ")
            if again.strip().lower() not in ("y", "yes", "c", "co", "có"):
                break
            k = ask_k(p)


if __name__ == "__main__":
    main()
