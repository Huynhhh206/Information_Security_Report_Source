"""
AES-128 tự cài đặt: key expansion, SubBytes, ShiftRows, MixColumns,
AddRoundKey, mã hóa/giải mã một block; chế độ CBC + PKCS#7 cho thông điệp.
Khóa được tạo = 16 byte đầu của SHA-256(tên đầy đủ).
"""
import secrets
import time
import unicodedata
from sha256_custom import sha256
from test_log import log_result

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
INV_SBOX = [0]*256
for i,v in enumerate(SBOX): INV_SBOX[v] = i
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def xtime(a):
    return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff

def gf_mul(a, b):
    result = 0
    while b:
        if b & 1: result ^= a
        a = xtime(a)
        b >>= 1
    return result

def normalize_name(full_name):
    """Bỏ dấu, viết hoa, gộp khoảng trắng: 'Nguyễn Lương Huynh' -> 'NGUYEN LUONG HUYNH'."""
    text = full_name.replace("Đ", "D").replace("đ", "d")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return " ".join(text.upper().split())


def key_from_full_name(full_name):
    """Khóa AES-128 = 16 byte đầu của SHA-256(họ tên đã chuẩn hóa)."""
    return bytes.fromhex(sha256(normalize_name(full_name)))[:16]

def expand_key(key):
    if len(key) != 16: raise ValueError("AES-128 yêu cầu khóa 16 byte")
    words = [list(key[i:i+4]) for i in range(0,16,4)]
    for i in range(4,44):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[x] for x in temp]
            temp[0] ^= RCON[i//4]
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    return [sum(words[4*r:4*r+4], []) for r in range(11)]

def add_round_key(s, key):
    for i in range(16): s[i] ^= key[i]

def sub_bytes(s): return [SBOX[x] for x in s]
def inv_sub_bytes(s): return [INV_SBOX[x] for x in s]

def shift_rows(s):
    return [s[0],s[5],s[10],s[15], s[4],s[9],s[14],s[3],
            s[8],s[13],s[2],s[7], s[12],s[1],s[6],s[11]]

def inv_shift_rows(s):
    return [s[0],s[13],s[10],s[7], s[4],s[1],s[14],s[11],
            s[8],s[5],s[2],s[15], s[12],s[9],s[6],s[3]]

def mix_columns(s):
    out = s[:]
    for c in range(4):
        i=4*c; a=s[i:i+4]
        out[i]   = gf_mul(a[0],2)^gf_mul(a[1],3)^a[2]^a[3]
        out[i+1] = a[0]^gf_mul(a[1],2)^gf_mul(a[2],3)^a[3]
        out[i+2] = a[0]^a[1]^gf_mul(a[2],2)^gf_mul(a[3],3)
        out[i+3] = gf_mul(a[0],3)^a[1]^a[2]^gf_mul(a[3],2)
    return out

def inv_mix_columns(s):
    out=s[:]
    for c in range(4):
        i=4*c; a=s[i:i+4]
        out[i]   = gf_mul(a[0],14)^gf_mul(a[1],11)^gf_mul(a[2],13)^gf_mul(a[3],9)
        out[i+1] = gf_mul(a[0],9)^gf_mul(a[1],14)^gf_mul(a[2],11)^gf_mul(a[3],13)
        out[i+2] = gf_mul(a[0],13)^gf_mul(a[1],9)^gf_mul(a[2],14)^gf_mul(a[3],11)
        out[i+3] = gf_mul(a[0],11)^gf_mul(a[1],13)^gf_mul(a[2],9)^gf_mul(a[3],14)
    return out

def encrypt_block(block, round_keys):
    if len(block)!=16: raise ValueError("Block phải có đúng 16 byte")
    s=list(block); add_round_key(s,round_keys[0])
    for r in range(1,10):
        s=sub_bytes(s); s=shift_rows(s); s=mix_columns(s); add_round_key(s,round_keys[r])
    s=sub_bytes(s); s=shift_rows(s); add_round_key(s,round_keys[10])
    return bytes(s)

def decrypt_block(block, round_keys):
    s=list(block); add_round_key(s,round_keys[10]); s=inv_shift_rows(s); s=inv_sub_bytes(s)
    for r in range(9,0,-1):
        add_round_key(s,round_keys[r]); s=inv_mix_columns(s); s=inv_shift_rows(s); s=inv_sub_bytes(s)
    add_round_key(s,round_keys[0])
    return bytes(s)

def pad(data):
    n=16-len(data)%16
    return data+bytes([n])*n

def unpad(data):
    if not data: raise ValueError("Dữ liệu rỗng")
    n=data[-1]
    if n<1 or n>16 or data[-n:]!=bytes([n])*n: raise ValueError("Padding không hợp lệ")
    return data[:-n]

def encrypt_cbc(plaintext, key, iv=None):
    iv = iv or secrets.token_bytes(16)
    if len(iv)!=16: raise ValueError("IV phải có 16 byte")
    rk=expand_key(key); data=pad(plaintext); out=b""; prev=iv
    for i in range(0,len(data),16):
        block=bytes(a^b for a,b in zip(data[i:i+16],prev))
        prev=encrypt_block(block,rk); out+=prev
    return iv,out

def decrypt_cbc(iv, ciphertext, key):
    if len(iv)!=16 or not ciphertext or len(ciphertext)%16: raise ValueError("IV/ciphertext không hợp lệ")
    rk=expand_key(key); out=b""; prev=iv
    for i in range(0,len(ciphertext),16):
        block=ciphertext[i:i+16]
        dec=decrypt_block(block,rk)
        out+=bytes(a^b for a,b in zip(dec,prev)); prev=block
    return unpad(out)

def self_test():
    # Vector kiểm thử AES-128 chuẩn FIPS-197 (Appendix B và Appendix C.1).
    for key_hex, plain_hex, cipher_hex in [
        ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
         "3925841d02dc09fbdc118597196a0b32"),
        ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
         "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ]:
        rk = expand_key(bytes.fromhex(key_hex))
        plain = bytes.fromhex(plain_hex)
        encrypted = encrypt_block(plain, rk)
        assert encrypted.hex() == cipher_hex, encrypted.hex()
        assert decrypt_block(encrypted, rk) == plain
    # Vector CBC của NIST SP 800-38A (F.2.1), bốn khối đầu.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    expected = ("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
    _, ct = encrypt_cbc(plain, key, iv)
    assert ct[:64].hex() == expected
    # Mã hóa rồi giải mã với nhiều độ dài thông điệp.
    for n in range(0, 40):
        test = bytes(range(n))
        iv2, ct = encrypt_cbc(test, key)
        assert decrypt_cbc(iv2, ct, key) == test
    # Khóa tạo từ họ tên: có dấu, không dấu, viết thường đều ra cùng một khóa.
    expected_key = "4955190b027604c857aaec2d7cb6f892"
    for name in ["NGUYEN LUONG HUYNH", "Nguyễn Lương Huynh", "nguyen  luong huynh"]:
        assert key_from_full_name(name).hex() == expected_key, name
    print("[PASS] AES-128: FIPS-197, SP 800-38A CBC, nhiều độ dài, khóa từ họ tên")


# ----------------------------------------------------------------------
# Phần hiển thị từng bước (chỉ để học và đối chiếu; không dùng trong mã hóa thật)
# ----------------------------------------------------------------------
def print_matrices(items):
    """In nhiều trạng thái 4x4 cạnh nhau. Trạng thái lưu theo cột: byte thứ 4*c + r nằm ở hàng r, cột c."""
    width = max(11, max(len(title) for title, _ in items))
    print("  " + "   ".join(f"{title:<{width}}" for title, _ in items))
    for r in range(4):
        cells = []
        for _, state in items:
            row = " ".join(f"{state[4 * c + r]:02X}" for c in range(4))
            cells.append(f"{row:<{width}}")
        print("  " + "   ".join(cells))


def hexline(data):
    return " ".join(f"{b:02X}" for b in data)


def show_key_schedule(key):
    """In 11 khóa vòng và cách tính từ đầu tiên của mỗi khóa (RotWord, SubWord, Rcon)."""
    rks = expand_key(key)
    print("--- Mở rộng khóa: 11 khóa vòng (mỗi khóa 16 byte, in theo thứ tự byte) ---")
    print(f"  K0  = {hexline(rks[0])}   (chính là khóa gốc)")
    for r in range(1, 11):
        prev_word = rks[r - 1][12:16]
        rot = prev_word[1:] + prev_word[:1]
        sub = [SBOX[x] for x in rot]
        g = sub[:]
        g[0] ^= RCON[r]
        first = [a ^ b for a, b in zip(rks[r - 1][0:4], g)]
        print(f"  K{r:<2} = {hexline(rks[r])}")
        print(f"        từ đầu: từ cuối K{r-1} = {hexline(prev_word)} -> RotWord {hexline(rot)} "
              f"-> SubWord {hexline(sub)} -> XOR Rcon {RCON[r]:02X} = {hexline(g)}; "
              f"từ đầu K{r} = từ đầu K{r-1} XOR kết quả = {hexline(first)}")
    return rks


def encrypt_block_steps(block, rks):
    """Mã hóa một khối 16 byte và in ma trận trạng thái sau từng phép biến đổi."""
    s = list(block)
    k0 = rks[0]
    t = s[:]
    add_round_key(t, k0)
    print("Vòng 0: AddRoundKey ban đầu")
    print_matrices([("Trạng thái S", s), ("Khóa K0", k0), ("S XOR K0", t)])
    s = t
    for r in range(1, 11):
        a = sub_bytes(s)
        b = shift_rows(a)
        items = [("SubBytes", a), ("ShiftRows", b)]
        if r < 10:
            c = mix_columns(b)
            items.append(("MixColumns", c))
        else:
            c = b
        d = c[:]
        add_round_key(d, rks[r])
        items += [(f"Khóa K{r}", rks[r]), ("AddRoundKey", d)]
        print(f"Vòng {r}:" + ("  (vòng cuối, bỏ MixColumns)" if r == 10 else ""))
        print_matrices(items)
        s = d
    return bytes(s)


def decrypt_block_steps(block, rks):
    """Giải mã một khối 16 byte và in ma trận trạng thái sau từng phép biến đổi ngược."""
    s = list(block)
    t = s[:]
    add_round_key(t, rks[10])
    a = inv_shift_rows(t)
    b = inv_sub_bytes(a)
    print("Vòng 10 (ngược):")
    print_matrices([("Bản mã", s), ("Khóa K10", rks[10]), ("AddRoundKey", t),
                    ("InvShiftRows", a), ("InvSubBytes", b)])
    s = b
    for r in range(9, 0, -1):
        t = s[:]
        add_round_key(t, rks[r])
        m = inv_mix_columns(t)
        sh = inv_shift_rows(m)
        sb = inv_sub_bytes(sh)
        print(f"Vòng {r} (ngược):")
        print_matrices([(f"Khóa K{r}", rks[r]), ("AddRoundKey", t), ("InvMixColumns", m),
                        ("InvShiftRows", sh), ("InvSubBytes", sb)])
        s = sb
    t = s[:]
    add_round_key(t, rks[0])
    print("Vòng 0 (ngược): AddRoundKey cuối")
    print_matrices([("Trạng thái", s), ("Khóa K0", rks[0]), ("Bản rõ", t)])
    return bytes(t)


def encrypt_cbc_steps(plaintext, key, iv, max_blocks=1):
    """Giống encrypt_cbc nhưng in từng bước. Chỉ in chi tiết max_blocks khối đầu."""
    rks = show_key_schedule(key)
    data = pad(plaintext)
    n = len(data) - len(plaintext)
    blocks = len(data) // 16
    print(f"\n--- Đệm PKCS#7: thêm {n} byte 0x{n:02X}; tổng {len(data)} byte = {blocks} khối ---")
    print(f"  IV = {hexline(iv)}")
    if blocks > max_blocks:
        print(f"(Chỉ in chi tiết {max_blocks} khối đầu, các khối còn lại vẫn được mã hóa đầy đủ.)")
    out = b""
    prev = iv
    for idx in range(blocks):
        p = data[idx * 16:(idx + 1) * 16]
        x = bytes(a ^ b for a, b in zip(p, prev))
        if idx < max_blocks:
            print(f"\n==================== KHỐI {idx + 1}/{blocks} ====================")
            print("CBC: lấy bản rõ XOR với IV (khối đầu) hoặc với bản mã của khối trước")
            print_matrices([("Bản rõ P", list(p)), ("IV / mã trước", list(prev)), ("P XOR trước", list(x))])
            c = encrypt_block_steps(x, rks)
            print(f"Bản mã khối {idx + 1}: {c.hex()}")
        else:
            c = encrypt_block(x, rks)
        out += c
        prev = c
    assert out == encrypt_cbc(plaintext, key, iv)[1], "Phần in từng bước cho kết quả khác với encrypt_cbc()"
    return iv, out


def decrypt_cbc_steps(iv, ciphertext, key, max_blocks=1):
    """Giống decrypt_cbc nhưng in từng bước. Chỉ in chi tiết max_blocks khối đầu."""
    rks = expand_key(key)
    blocks = len(ciphertext) // 16
    out = b""
    prev = iv
    for idx in range(blocks):
        c = ciphertext[idx * 16:(idx + 1) * 16]
        if idx < max_blocks:
            print(f"\n==================== GIẢI MÃ KHỐI {idx + 1}/{blocks} ====================")
            dec = decrypt_block_steps(c, rks)
            p = bytes(a ^ b for a, b in zip(dec, prev))
            print("CBC: kết quả giải mã XOR với IV (khối đầu) hoặc với bản mã của khối trước")
            print_matrices([("Sau giải mã", list(dec)), ("IV / mã trước", list(prev)), ("Bản rõ P", list(p))])
        else:
            p = bytes(a ^ b for a, b in zip(decrypt_block(c, rks), prev))
        out += p
        prev = c
    result = unpad(out)
    assert result == decrypt_cbc(iv, ciphertext, key), "Phần in từng bước cho kết quả khác với decrypt_cbc()"
    return result


# ----------------------------------------------------------------------
# Chương trình tương tác
# ----------------------------------------------------------------------
HEX = "0123456789abcdefABCDEF"


def parse_hex(text, nbytes, label):
    t = text.replace(" ", "").strip()
    if len(t) != 2 * nbytes or any(c not in HEX for c in t):
        raise ValueError(f"{label} phải gồm đúng {2 * nbytes} ký tự hex (0-9, a-f)")
    return bytes.fromhex(t)


def read_key(text):
    """Khóa: 32 ký tự hex, hoặc họ tên (băm bằng SHA-256 rồi lấy 16 byte đầu)."""
    t = text.replace(" ", "").strip()
    if len(t) == 32 and all(c in HEX for c in t):
        return bytes.fromhex(t), "hex"
    if not normalize_name(text):
        raise ValueError("Họ tên hoặc khóa đang để trống")
    return key_from_full_name(text), "họ tên"


def read_block(text):
    """Một khối 16 byte: 32 ký tự hex, hoặc đúng 16 byte văn bản."""
    t = text.replace(" ", "").strip()
    if len(t) == 32 and all(c in HEX for c in t):
        return bytes.fromhex(t)
    data = text.encode("utf-8")
    if len(data) != 16:
        raise ValueError(f"Khối phải là 32 ký tự hex hoặc đúng 16 byte văn bản (bạn nhập {len(data)} byte)")
    return data


def cbc_report(name, message, iv_hex=""):
    """Mã hóa CBC thông điệp, giải mã lại để kiểm tra (dùng cho chạy hàng loạt)."""
    key, how = read_key(name)
    data = message.encode("utf-8")
    iv = parse_hex(iv_hex, 16, "IV") if iv_hex.strip() else None
    iv_used, cipher = encrypt_cbc(data, key, iv)
    recovered = decrypt_cbc(iv_used, cipher, key)
    return {"key": key.hex(), "bytes": len(data), "pad": 16 - len(data) % 16, "blocks": len(cipher) // 16,
            "iv": iv_used.hex(), "cipher": cipher.hex(), "ok": recovered == data}


def block_report(key_text, block_text):
    """Mã hóa rồi giải mã MỘT khối 16 byte (không đệm, không CBC) để so với vector chuẩn."""
    key, _ = read_key(key_text)
    block = read_block(block_text)
    rk = expand_key(key)
    cipher = encrypt_block(block, rk)
    return {"key": key.hex(), "block": block.hex(), "cipher": cipher.hex(),
            "ok": decrypt_block(cipher, rk) == block}


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
    while True:
        raw = input(prompt).strip()
        if raw == "":
            return default
        if raw.isdigit() and int(raw) >= 1:
            return int(raw)
        print("  Hãy nhập một số nguyên dương.")


def read_iv(prompt):
    """IV nhập dạng hex 32 ký tự; Enter = chọn ngẫu nhiên (trả về None)."""
    while True:
        raw = input(prompt).strip().replace(" ", "")
        if raw == "":
            return None
        try:
            iv = bytes.fromhex(raw)
        except ValueError:
            iv = b""
        if len(iv) == 16:
            return iv
        print("  IV phải gồm đúng 32 chữ số hex (16 byte), hãy nhập lại.")


def main():
    print("=== AES-128 FROM SCRATCH ===")
    self_test()
    preset_name = "Nguyễn Lương Huynh"
    preset_message = "UNOFTRANSPORTHCM"
    while True:
        print("\nChọn:")
        print(f"  1. Dùng giá trị gán sẵn: họ tên \"{preset_name}\", bản rõ \"{preset_message}\"")
        print("     (IV toàn số 0, nên khối đầu trùng với ví dụ tính tay: bản rõ XOR IV = bản rõ)")
        print("  2. Nhập giá trị khác")
        print("  0. Thoát")
        choice = read_choice("Lựa chọn: ", ("0", "1", "2"))
        if choice == "0":
            print("Tạm biệt.")
            break
        if choice == "1":
            name, message, iv = preset_name, preset_message.encode("utf-8"), bytes(16)
        else:
            name = ""
            while not normalize_name(name):
                name = input("Nhập họ và tên đầy đủ (đúng theo yêu cầu đề): ")
            message = input("Nhập thông điệp cần mã hóa: ").encode("utf-8")
            iv = read_iv("IV dạng hex 32 ký tự (Enter = chọn ngẫu nhiên): ")
        if iv is None:
            iv = secrets.token_bytes(16)

        key = key_from_full_name(name)
        print("\nHọ tên sau khi chuẩn hóa:", normalize_name(name))
        print("SHA-256(họ tên):", sha256(normalize_name(name)))
        print("Khóa AES-128 (128 bit đầu):", key.hex())

        steps = ask_yes_no("Hiển thị các bước tính? (y/N): ")
        max_blocks = read_positive("  Số khối in chi tiết (Enter = 1): ", 1) if steps else 0
        if steps:
            _, cipher = encrypt_cbc_steps(message, key, iv, max_blocks)
        else:
            _, cipher = encrypt_cbc(message, key, iv)
        print("\n--- KẾT QUẢ MÃ HÓA ---")
        print("Bản rõ:", message.decode("utf-8"))
        print("IV:", iv.hex())
        print("Bản mã:", cipher.hex())

        if steps:
            recovered = decrypt_cbc_steps(iv, cipher, key, max_blocks)
        else:
            recovered = decrypt_cbc(iv, cipher, key)
        print("\n--- KẾT QUẢ GIẢI MÃ ---")
        print("Bản rõ sau giải mã:", recovered.decode("utf-8"))
        assert recovered == message
        print("[PASS] Kiểm tra giải mã trùng bản rõ")
        n = log_result("AES-128 CBC", f"họ tên={name!r}, thông điệp={message.decode('utf-8')!r}, iv={iv.hex()}",
                       f"khóa={key.hex()}, {len(message)} byte, bản mã={cipher.hex()}", recovered == message)
        print(f"(đã ghi lần thử số {n} vào ket_qua_test.csv)")


if __name__ == "__main__":
    main()
