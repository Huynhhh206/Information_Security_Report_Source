"""
Diffie-Hellman key exchange tự cài đặt.
Nhóm mặc định: MODP 2048-bit, RFC 3526 group 14 (p là số nguyên tố an toàn, g = 2).
Có thêm nhóm 1536-bit (RFC 3526 group 5) để so sánh tốc độ.
Với hai nhóm này, g = 2 sinh nhóm con bậc q = (p-1)/2, không sinh toàn bộ Z_p*.
Đây là minh họa trao đổi khóa; không phải giao thức xác thực hai bên.
"""
import secrets
import time
from sha256_custom import sha256
from number_theory import is_probable_prime

P_2048 = int("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)

P_1536 = int("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)

P = P_2048
G = 2
Q = (P - 1) // 2          # bậc của nhóm con do g = 2 sinh ra


def mod_pow(base, exponent, modulus):
    """Lũy thừa modulo bằng bình phương-có-nhân."""
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def generate_private_key(p=P):
    return secrets.randbelow(p - 3) + 2          # 2 <= private <= p-2


def public_key(private, p=P, g=G):
    if not 2 <= private <= p - 2:
        raise ValueError("Private key ngoài miền hợp lệ")
    return mod_pow(g, private, p)


def is_valid_public_key(their_public, p=P, q=Q):
    """Kiểm tra khóa công khai nhận được.
    Luôn kiểm tra 2 <= y <= p-2. Nếu có q thì kiểm tra thêm y^q = 1 (mod p),
    tức y nằm trong nhóm con bậc q (chống small-subgroup)."""
    if not 2 <= their_public <= p - 2:
        return False
    if q is not None and mod_pow(their_public, q, p) != 1:
        return False
    return True


def shared_secret(their_public, my_private, p=P, q=Q):
    if not is_valid_public_key(their_public, p, q):
        raise ValueError("Public key không hợp lệ")
    return mod_pow(their_public, my_private, p)


def derive_key(shared, p=P):
    """Băm khóa chung bằng SHA-256 (tự cài), lấy 16 byte đầu làm khóa AES-128."""
    length = (p.bit_length() + 7) // 8
    return bytes.fromhex(sha256(shared.to_bytes(length, "big")))[:16]


def read_int(prompt, minimum=None, maximum=None, allow_blank=False):
    """Đọc một số nguyên từ bàn phím (thập phân hoặc dạng 0x...). Nhập sai thì hỏi lại.
    Nếu allow_blank=True thì bấm Enter trả về None."""
    while True:
        raw = input(prompt).strip().replace(" ", "").replace("_", "")
        if raw == "":
            if allow_blank:
                return None
            print("  Chưa nhập giá trị, hãy nhập lại.")
            continue
        try:
            value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            print("  Không phải số nguyên, hãy nhập lại (thập phân hoặc 0x...).")
            continue
        if minimum is not None and value < minimum:
            print(f"  Giá trị phải >= {minimum}, hãy nhập lại.")
            continue
        if maximum is not None and value > maximum:
            print(f"  Giá trị phải <= {maximum}, hãy nhập lại.")
            continue
        return value


def read_prime(prompt, minimum=5, allow_blank=False):
    """Đọc số nguyên tố p. Số không nguyên tố bị từ chối (kiểm tra bằng Miller-Rabin)."""
    while True:
        value = read_int(prompt, minimum=minimum, allow_blank=allow_blank)
        if value is None:
            return None
        if is_probable_prime(value):
            return value
        print(f"  {value} không phải số nguyên tố (Miller-Rabin), hãy nhập lại.")


def read_choice(prompt, valid):
    """Hỏi đến khi người dùng nhập một lựa chọn hợp lệ."""
    while True:
        value = input(prompt).strip()
        if value in valid:
            return value
        print("  Lựa chọn không hợp lệ, hãy nhập lại.")


def self_test():
    # Ví dụ số nhỏ để đối chiếu bằng tay (g = 5 sinh toàn bộ Z_23*, nên không kiểm nhóm con).
    p, g, a, b = 23, 5, 6, 15
    A = mod_pow(g, a, p)
    B = mod_pow(g, b, p)
    s1 = shared_secret(B, a, p, None)
    s2 = shared_secret(A, b, p, None)
    assert (A, B, s1, s2) == (8, 19, 2, 2)
    # Các khóa không hợp lệ phải bị từ chối.
    for bad in (0, 1, p - 1, p):
        assert not is_valid_public_key(bad, p, None)
    # Nhóm 2048-bit: g = 2 phải có bậc q, hai bên ra cùng khóa chung và cùng khóa AES.
    assert mod_pow(G, Q, P) == 1 and G != 1
    alice = generate_private_key()
    bob = generate_private_key()
    A = public_key(alice)
    B = public_key(bob)
    assert shared_secret(B, alice) == shared_secret(A, bob)
    assert derive_key(shared_secret(B, alice)) == derive_key(shared_secret(A, bob))
    assert not is_valid_public_key(P - 1)          # phần tử bậc 2 bị loại
    print("[PASS] Ví dụ nhỏ p=23, kiểm tra khóa không hợp lệ, trao đổi khóa nhóm 2048-bit")


def run_exchange(p, g, q, a, b):
    """Chạy một lần trao đổi khóa và in kết quả."""
    A = public_key(a, p, g)
    B = public_key(b, p, g)
    try:
        secret_a = shared_secret(B, a, p, q)
        secret_b = shared_secret(A, b, p, q)
    except ValueError as error:
        print("[LỖI]", error)
        return
    print("\n--- KẾT QUẢ ---")
    print("Tham số công khai: p =", p)
    print("g =", g)
    print("Số bí mật của Alice a =", a)
    print("Số bí mật của Bob   b =", b)
    print("Khóa công khai Alice A = g^a mod p =", A)
    print("Khóa công khai Bob   B = g^b mod p =", B)
    print("Khóa chung phía Alice = B^a mod p =", secret_a)
    print("Khóa chung phía Bob   = A^b mod p =", secret_b)
    print("Hai khóa chung bằng nhau:", secret_a == secret_b)
    print("Khóa AES-128 suy ra (hex):", derive_key(secret_a, p).hex())
    assert secret_a == secret_b


def main():
    print("=== DIFFIE-HELLMAN FROM SCRATCH ===")
    self_test()
    while True:
        print("\nChọn:")
        print("  1. Dùng giá trị gán sẵn (ví dụ tay): p = 23, g = 5, a = 6, b = 15")
        print("  2. Nhập giá trị khác")
        print("  0. Thoát")
        choice = read_choice("Lựa chọn: ", ("0", "1", "2"))
        if choice == "0":
            print("Tạm biệt.")
            break
        if choice == "1":
            p, g, q, a, b = 23, 5, None, 6, 15
        else:
            p = read_prime("Nhập số nguyên tố p (Enter = nhóm 2048-bit RFC 3526 nhóm 14): ",
                           minimum=5, allow_blank=True)
            if p is None:
                p, g, q = P, G, Q
            else:
                g = read_int(f"Nhập phần tử sinh g (2 <= g <= {p - 2}): ", 2, p - 2)
                q = Q if (p == P and g == G) else None   # chỉ kiểm tra nhóm con khi dùng đúng nhóm chuẩn
            a = read_int(f"Số bí mật của Alice a (2 <= a <= {p - 2}, Enter = chọn ngẫu nhiên): ",
                         2, p - 2, allow_blank=True)
            if a is None:
                a = generate_private_key(p)
            b = read_int(f"Số bí mật của Bob b (2 <= b <= {p - 2}, Enter = chọn ngẫu nhiên): ",
                         2, p - 2, allow_blank=True)
            if b is None:
                b = generate_private_key(p)
        run_exchange(p, g, q, a, b)


if __name__ == "__main__":
    main()
