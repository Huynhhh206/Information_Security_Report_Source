"""Chạy hàng loạt các lần thử từ file cases.txt rồi ghi kết quả vào ket_qua_test.csv.

Dùng:
    python run_cases.py              # đọc cases.txt
    python run_cases.py my_cases.txt # đọc file khác

Mỗi dòng là một lần thử. Dòng trống hoặc bắt đầu bằng # bị bỏ qua. Các phần cách nhau bằng dấu |
(khoảng trắng đầu và cuối mỗi phần bị bỏ qua):

    sha256     | chuỗi cần băm | [đầu của digest mong đợi]
    aes        | họ tên hoặc khóa hex | thông điệp | [IV hex]
    aes-khoi   | khóa | khối 16 byte (32 hex hoặc 16 ký tự) | [đầu của bản mã mong đợi]
    dh         | p g a b
    elgamal    | p g x k H [H']              (k = - để chọn ngẫu nhiên)
    elgamal-tn | small hoặc big | thông điệp | [thông điệp bị sửa] | [x] | [k]
    elgamal-kt | p g y H r s | [dung hoặc sai: kết quả bạn kỳ vọng]
"""
import sys

import aes128 as AES
import diffie_hellman as DH
import elgamal_signature as EG
import sha256_custom as SHA
from test_log import log_result

sn = DH.show_number


def numbers(text, count_min, count_max):
    try:
        values = [int(t, 0) for t in text.split()]
    except ValueError:
        raise ValueError("Các tham số phải là số nguyên, cách nhau bằng dấu cách")
    if not count_min <= len(values) <= count_max:
        raise ValueError(f"Cần {count_min} đến {count_max} số, nhận được {len(values)}")
    return values


def case_sha256(args):
    text = args[0] if args else ""
    expected = args[1] if len(args) > 1 else ""
    r = SHA.hash_report(text)
    ok = r["digest"].startswith(expected.lower()) if expected else None
    return "SHA-256", f"chuỗi={text!r}", f"{r['bytes']} byte, {r['blocks']} khối, digest={r['digest']}", ok


def case_aes(args):
    iv = args[2] if len(args) > 2 else ""
    r = AES.cbc_report(args[0], args[1], iv)
    return ("AES-128 CBC", f"họ tên/khóa={args[0]!r}, thông điệp={args[1]!r}, iv={r['iv']}",
            f"khóa={r['key']}, {r['bytes']} byte + đệm {r['pad']}, bản mã={r['cipher']}", r["ok"])


def case_aes_block(args):
    r = AES.block_report(args[0], args[1])
    expected = args[2].lower() if len(args) > 2 else ""
    ok = r["ok"] and (r["cipher"].startswith(expected) if expected else True)
    return "AES-128 một khối", f"khóa={r['key']}, bản rõ={r['block']}", f"bản mã={r['cipher']}", ok


def case_dh(args):
    p, g, a, b = numbers(args[0], 4, 4)
    r = DH.exchange_report(p, g, a, b)
    order = f", bậc g={r['order']}" if r["order"] else ""
    return ("Diffie-Hellman", f"p={sn(p)}, g={g}, a={sn(a)}, b={sn(b)}",
            f"A={sn(r['A'])}, B={sn(r['B'])}, K_Alice={sn(r['key_alice'])}, K_Bob={sn(r['key_bob'])}{order}",
            r["equal"])


def case_elgamal(args):
    values = args[0].split()
    if len(values) not in (5, 6):
        raise ValueError("Cần p g x k H [H']")
    p, g, x = int(values[0]), int(values[1]), int(values[2])
    k = None if values[3] == "-" else int(values[3])
    h = int(values[4])
    h2 = int(values[5]) if len(values) == 6 else None
    r = EG.sign_report(p, g, x, k, h, h2)
    out = f"y={r['y']}, (r,s)=({r['r']},{r['s']}), VT={r['left']}, VP={r['right']}, hợp lệ={r['valid']}"
    ok = r["valid"]
    if h2 is not None:
        out += f"; H'={h2}: VP={r['right_tampered']}, hợp lệ={r['valid_tampered']}"
        ok = ok and (r["valid_tampered"] if r["identical"] else not r["valid_tampered"])
    return "ElGamal ký", f"p={p}, g={g}, x={x}, k={values[3]}, H={h}", out, ok


def case_elgamal_msg(args):
    big = args[0].lower() == "big"
    message = args[1]
    tampered = args[2] if len(args) > 2 and args[2] else None
    x = int(args[3]) if len(args) > 3 and args[3] else None
    k = int(args[4]) if len(args) > 4 and args[4] else None
    r = EG.message_report(message, tampered, big, x, k)
    out = f"h={sn(r['h'])}, r={sn(r['r'])}, s={sn(r['s'])}, gốc hợp lệ={r['valid']}"
    ok = r["valid"]
    if tampered is not None:
        out += f"; bản sửa hợp lệ={r['valid_tampered']}" + (", h trùng (p nhỏ)" if r["collision"] else "")
        ok = ok and (r["valid_tampered"] if r["identical"] else not r["valid_tampered"])
    return ("ElGamal thông điệp", f"nhóm={r['p'].bit_length()} bit, thông điệp={message!r}, sửa={tampered!r}", out, ok)


def case_elgamal_verify(args):
    p, g, y, h, r_, s_ = numbers(args[0], 6, 6)
    r = EG.verify_report(p, g, y, h, r_, s_)
    expected = args[1].lower() if len(args) > 1 else ""
    ok = None if not expected else (r["valid"] == (expected == "dung"))
    out = (f"VT={r['left'] if r['in_range'] else 'ngoài miền'}, VP={r['right']}, hợp lệ={r['valid']}")
    return "ElGamal kiểm tra chữ ký", f"p={p}, g={g}, y={y}, H={h}, (r,s)=({r_},{s_})", out, ok


HANDLERS = {"sha256": case_sha256, "aes": case_aes, "aes-khoi": case_aes_block, "dh": case_dh,
            "elgamal": case_elgamal, "elgamal-tn": case_elgamal_msg, "elgamal-kt": case_elgamal_verify}


def main(path="cases.txt"):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        print(f"Không tìm thấy file {path}")
        return
    done = passed = failed = 0
    for number, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("|")
        name, args = parts[0].strip().lower(), [p.strip() for p in parts[1:]]
        handler = HANDLERS.get(name)
        done += 1
        if handler is None:
            print(f"{done:>3}. (dòng {number}) Không biết loại thử '{name}'")
            failed += 1
            continue
        try:
            label, inputs, outputs, ok = handler(args)
        except (ValueError, IndexError) as e:
            label, inputs, outputs, ok = name, " | ".join(args), f"lỗi: {e}", False
        log_result(label, inputs, outputs, ok)
        status = {True: "Đạt", False: "Không đạt", None: "-"}[ok]
        print(f"{done:>3}. {label}: {inputs}\n     -> {outputs} [{status}]")
        passed += ok is True
        failed += ok is False
    print(f"\nĐã chạy {done} lần thử: {passed} đạt, {failed} không đạt. Kết quả đã ghi vào ket_qua_test.csv")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cases.txt")
