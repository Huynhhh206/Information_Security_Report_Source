"""Các hàm số học dùng chung cho Diffie-Hellman và ElGamal.

Các hàm:
    mod_exp(base, exp, mod)        -> (base ** exp) % mod
    egcd(a, b)                     -> (g, x, y) sao cho a*x + b*y = g = gcd(a, b)
    mod_inv(a, m)                  -> x sao cho (a * x) % m == 1
    is_probable_prime(n)           -> kiểm tra nguyên tố bằng Miller-Rabin
    generate_prime(bits)           -> số nguyên tố ngẫu nhiên có đúng `bits` bit
    generate_safe_prime(bits)      -> (p, q) với p = 2q + 1, cả hai đều nguyên tố
    find_generator(p, q)           -> phần tử sinh g của Z_p* (p = 2q + 1)

Cách chạy:
    python number_theory.py            # menu: kiểm tra nghịch đảo modular / Miller-Rabin
    python number_theory.py test       # chạy nhiều bộ kiểm thử tự động
    python number_theory.py gen 256    # sinh số nguyên tố an toàn 256 bit và một phần tử sinh

Trong menu, chọn 0 (hoặc gõ q ở bất kỳ câu hỏi nào) để thoát.
"""

import math
import random
import secrets
import sys
import time
from typing import Optional, Tuple


# ----------------------------------------------------------------------
# Số học modular
# ----------------------------------------------------------------------
def mod_exp(base: int, exp: int, mod: int) -> int:
    """Tính (base ** exp) % mod bằng bình phương liên tiếp."""
    if exp < 0:
        raise ValueError("số mũ phải không âm")
    if mod < 1:
        raise ValueError("modulo phải >= 1")
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def egcd(a: int, b: int, trace: bool = False) -> Tuple[int, int, int]:
    """Euclid mở rộng. Trả về (g, x, y) sao cho a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    if trace:
        print(f"{'q':>4} {'old_r':>7} {'r':>7} {'old_y':>7} {'y':>7}")
        print(f"{'':>4} {old_r:>7} {r:>7} {old_y:>7} {y:>7}")
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
        if trace:
            print(f"{q:>4} {old_r:>7} {r:>7} {old_y:>7} {y:>7}")
    return old_r, old_x, old_y


def mod_inv(a: int, m: int, trace: bool = False) -> int:
    """Trả về x trong [0, m) sao cho (a * x) % m == 1. Báo ValueError nếu không tồn tại."""
    if m < 1:
        raise ValueError("m phải >= 1")
    g, _, y = egcd(m, a % m, trace)      # m*x + (a % m)*y = g
    if g != 1:
        raise ValueError(f"không có nghịch đảo: gcd({a}, {m}) = {g}")
    return y % m


# ----------------------------------------------------------------------
# Số nguyên tố
# ----------------------------------------------------------------------
def _small_primes(limit: int):
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            for j in range(i * i, limit + 1, i):
                sieve[j] = False
    return [i for i, is_p in enumerate(sieve) if is_p]


SMALL_PRIMES = _small_primes(1000)       # dùng để thử chia nhanh
FIXED_BASES = SMALL_PRIMES[:12]          # 2, 3, 5, ..., 37


def miller_rabin_round(n: int, a: int, trace: bool = False) -> bool:
    """Một vòng Miller-Rabin cho n lẻ >= 5 và cơ sở 2 <= a <= n - 2.

    True  -> n qua vòng này ("có thể là số nguyên tố").
    False -> n chắc chắn là hợp số.
    """
    d, s = n - 1, 0
    while d % 2 == 0:                    # viết n - 1 = 2^s * d với d lẻ
        d //= 2
        s += 1
    x = mod_exp(a, d, n)
    if trace:
        print(f"n - 1 = 2^{s} * {d}")
        print(f"x = {a}^{d} mod {n} = {x}")
    if x == 1 or x == n - 1:
        if trace:
            print("x bằng 1 hoặc n - 1, nên n qua vòng kiểm tra với cơ sở này.")
        return True
    for _ in range(s - 1):
        x = (x * x) % n
        if trace:
            print(f"bình phương: x = {x}")
        if x == n - 1:
            if trace:
                print("x đạt n - 1, nên n qua vòng kiểm tra với cơ sở này.")
            return True
    if trace:
        print("x không bao giờ đạt n - 1, nên n là hợp số.")
    return False


def is_probable_prime(n: int, extra_rounds: int = 20, trial: bool = True) -> bool:
    """Kiểm tra Miller-Rabin. Nếu trial = False thì bỏ bước thử chia cho số nguyên tố nhỏ
    (dùng trong kiểm thử để đánh giá riêng Miller-Rabin)."""
    if n < 2:
        return False
    if trial:
        for p in SMALL_PRIMES:
            if n == p:
                return True
            if n % p == 0:
                return False
        if n < 997 * 997:                # không có ước <= 997 nên n nguyên tố
            return True
    else:
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False
    bases = [a for a in FIXED_BASES if a <= n - 2]
    bases += [secrets.randbelow(n - 3) + 2 for _ in range(extra_rounds)] if n >= 5 else []
    return all(miller_rabin_round(n, a) for a in bases)


def generate_prime(bits: int) -> int:
    """Số nguyên tố ngẫu nhiên có đúng `bits` bit."""
    if bits < 2:
        raise ValueError("bits phải >= 2")
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1   # bit cao nhất bằng 1, số lẻ
        if is_probable_prime(n):
            return n


def generate_safe_prime(bits: int) -> Tuple[int, int]:
    """Trả về (p, q) với p = 2q + 1, p và q đều nguyên tố, p có `bits` bit."""
    if bits < 3:
        raise ValueError("bits phải >= 3")
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q


def find_generator(p: int, q: int) -> int:
    """Phần tử sinh nhỏ nhất g của Z_p* khi p = 2q + 1 là số nguyên tố an toàn.

    Bậc của g chia hết p - 1 = 2q nên chỉ có thể là 1, 2, q hoặc 2q.
    g^2 != 1 loại bậc 1 và 2; g^q != 1 loại bậc 1 và q. Còn lại bậc 2q.
    """
    if p != 2 * q + 1:
        raise ValueError("p phải bằng 2q + 1")
    for g in range(2, p - 1):
        if mod_exp(g, 2, p) != 1 and mod_exp(g, q, p) != 1:
            return g
    raise ValueError("không tìm thấy phần tử sinh")


def slow_is_prime(n: int) -> bool:
    """Thử chia. Chỉ dùng để kiểm tra các số nhỏ trong kiểm thử."""
    if n < 2:
        return False
    for i in range(2, math.isqrt(n) + 1):
        if n % i == 0:
            return False
    return True


# ----------------------------------------------------------------------
# Kiểm tra tương tác
# ----------------------------------------------------------------------
def read_int(prompt: str, minimum: Optional[int] = None) -> int:
    """Hỏi đến khi người dùng nhập một số nguyên. Gõ q để thoát chương trình."""
    while True:
        text = input(prompt).strip()
        if text.lower() in ("q", "quit"):
            print("Tạm biệt.")
            raise SystemExit(0)
        try:
            value = int(text)
        except ValueError:
            print("Hãy nhập một số nguyên.")
            continue
        if minimum is not None and value < minimum:
            print(f"Số phải >= {minimum}.")
            continue
        return value


def ask_text(prompt: str) -> str:
    text = input(prompt).strip()
    if text.lower() in ("q", "quit"):
        print("Tạm biệt.")
        raise SystemExit(0)
    return text


def check_inverse() -> None:
    a = read_int("a: ")
    m = read_int("m (>= 1): ", minimum=1)

    g = math.gcd(a, m)
    if g != 1:
        print(f"Không tồn tại nghịch đảo, vì gcd({a}, {m}) = {g} (phải bằng 1).\n")
        return

    mine = mod_inv(a, m)
    if (a * mine) % m != 1 % m or not 0 <= mine < m:
        print(f"LỖI: mod_inv trả về {mine}, nhưng ({a} * {mine}) % {m} khác 1\n")
        return
    print("mod_inv tự kiểm tra đạt: (a * x) % m == 1.")

    text = ask_text("Đáp án bạn tính tay (Enter để bỏ qua): ")
    if text:
        try:
            guess = int(text)
        except ValueError:
            print("Đó không phải số nguyên.")
        else:
            if (a * guess) % m == 1 % m:
                print("ĐÚNG")
            else:
                print(f"SAI: ({a} * {guess}) % {m} = {(a * guess) % m}, không phải 1.")
                print(f"Đáp án đúng là {mine}")

    if ask_text("Hiển thị các bước? (y/n): ").lower() == "y":
        mod_inv(a, m, trace=True)
    print()


def check_miller_rabin() -> None:
    n = read_int("n (lẻ, >= 5): ", minimum=5)
    if n % 2 == 0:
        print("n là số chẵn nên là hợp số (chia hết cho 2).\n")
        return
    a = read_int(f"Cơ sở a (từ 2 đến {n - 2}): ", minimum=2)
    if a > n - 2:
        print(f"Cơ sở phải <= {n - 2}.\n")
        return

    passes = miller_rabin_round(n, a)

    text = ask_text("Đáp án bạn tính tay: p = qua vòng kiểm tra, c = hợp số (Enter để bỏ qua): ").lower()
    if text in ("p", "c"):
        if (text == "p") == passes:
            print("ĐÚNG")
        else:
            right = "qua vòng kiểm tra (có thể là số nguyên tố)" if passes else "là hợp số"
            print(f"SAI. Với cơ sở {a}, n {right}.")
    elif text:
        print("Hãy nhập p hoặc c.")

    if ask_text("Hiển thị các bước? (y/n): ").lower() == "y":
        miller_rabin_round(n, a, trace=True)

    if passes:
        print("Qua một cơ sở KHÔNG chứng minh được n là số nguyên tố.")
    else:
        print(f"{n} chắc chắn là hợp số.")
    print(f"is_probable_prime({n}) với nhiều cơ sở cho kết quả: {is_probable_prime(n)}\n")


def interactive() -> None:
    print("Công cụ kiểm tra số học. Gõ q ở bất kỳ câu hỏi nào để thoát.\n")
    while True:
        print("  1) Nghịch đảo modular")
        print("  2) Miller-Rabin, một cơ sở")
        print("  0) Thoát")
        choice = ask_text("Chọn 1, 2 hoặc 0: ")
        print()
        if choice == "1":
            check_inverse()
        elif choice == "2":
            check_miller_rabin()
        elif choice == "0":
            print("Tạm biệt.")
            break
        else:
            print("Hãy nhập 1, 2 hoặc 0.\n")


# ----------------------------------------------------------------------
# Kiểm thử tự động và demo sinh số nguyên tố
# ----------------------------------------------------------------------
def random_test(cases: int = 5000) -> None:
    rng = random.Random(2026)            # seed cố định: mỗi lần chạy cho cùng các ca kiểm thử

    # nghịch đảo modular, egcd, mod_exp
    for i in range(cases):
        m = rng.randint(1, 10**6)
        a = rng.randint(-2 * m, 2 * m)
        g_true = math.gcd(a, m)

        g, x, y = egcd(m, a % m)
        if g != g_true or m * x + (a % m) * y != g:
            print(f"THẤT BẠI (egcd) ở ca {i}: a={a}, m={m}")
            sys.exit(1)

        if g_true == 1:
            inv = mod_inv(a, m)
            if not 0 <= inv < m or (a * inv) % m != 1 % m or inv != pow(a, -1, m):
                print(f"THẤT BẠI (mod_inv) ở ca {i}: a={a}, m={m}, nhận {inv}")
                sys.exit(1)
        else:
            try:
                mod_inv(a, m)
            except ValueError:
                pass
            else:
                print(f"THẤT BẠI: đáng lẽ phải báo lỗi ở ca {i}: a={a}, m={m}")
                sys.exit(1)

        e = rng.randint(0, 10**5)
        if mod_exp(a, e, m) != pow(a, e, m):
            print(f"THẤT BẠI (mod_exp) ở ca {i}: a={a}, e={e}, m={m}")
            sys.exit(1)
    print(f"đạt: egcd, mod_inv, mod_exp trên {cases} ca ngẫu nhiên")

    # Miller-Rabin riêng (không thử chia) so với thử chia
    for n in range(0, 20000):
        if is_probable_prime(n, trial=False) != slow_is_prime(n):
            print(f"THẤT BẠI (Miller-Rabin riêng) ở n={n}")
            sys.exit(1)
    print("đạt: Miller-Rabin riêng khớp với thử chia với 0 .. 19999")

    # các số đánh lừa được phép thử Fermat đơn giản
    for n in (341, 561, 1105, 1729, 2465, 2821, 6601):
        if is_probable_prime(n, trial=False):
            print(f"THẤT BẠI: {n} là hợp số nhưng qua Miller-Rabin")
            sys.exit(1)
    print("đạt: 341, 561, 1105, 1729, 2465, 2821, 6601 được nhận ra là hợp số")

    # số nguyên tố lớn đã biết và một hợp số lớn
    for e in (61, 89, 127):
        if not is_probable_prime(2**e - 1, trial=False):
            print(f"THẤT BẠI: 2^{e} - 1 là số nguyên tố nhưng bị loại")
            sys.exit(1)
    if is_probable_prime((2**61 - 1) * (2**89 - 1), trial=False):
        print("THẤT BẠI: tích của hai số nguyên tố bị chấp nhận")
        sys.exit(1)
    print("đạt: các số nguyên tố Mersenne 2^61-1, 2^89-1, 2^127-1 được chấp nhận; tích của chúng bị loại")

    # phần tử sinh và số nguyên tố an toàn (cỡ nhỏ, kiểm tra bằng thử chia)
    if find_generator(23, 11) != 5:
        print("THẤT BẠI: phần tử sinh nhỏ nhất của p = 23 phải là 5")
        sys.exit(1)
    for _ in range(5):
        p, q = generate_safe_prime(32)
        g = find_generator(p, q)
        seen_ok = (p == 2 * q + 1 and slow_is_prime(p) and slow_is_prime(q)
                   and p.bit_length() == 32 and mod_exp(g, 2, p) != 1
                   and mod_exp(g, q, p) != 1 and mod_exp(g, p - 1, p) == 1)
        if not seen_ok:
            print(f"THẤT BẠI: kiểm tra số nguyên tố an toàn / phần tử sinh sai với p={p}, q={q}, g={g}")
            sys.exit(1)
    print("đạt: 5 số nguyên tố an toàn 32 bit ngẫu nhiên và phần tử sinh của chúng")
    print("TẤT CẢ KIỂM THỬ ĐỀU ĐẠT")


def generate_demo(bits: int) -> None:
    start = time.perf_counter()
    p, q = generate_safe_prime(bits)
    g = find_generator(p, q)
    seconds = time.perf_counter() - start
    print(f"số bit của p = {p.bit_length()}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")
    print(f"thời gian = {seconds:.2f} giây")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        random_test()
    elif len(sys.argv) > 1 and sys.argv[1] == "gen":
        generate_demo(int(sys.argv[2]) if len(sys.argv) > 2 else 256)
    else:
        interactive()
