# Bộ code 4 thuật toán mật mã (Python, tự cài đặt)

AES-128, Diffie–Hellman, SHA-256, chữ ký ElGamal. Không dùng thư viện mật mã và không dùng `hashlib`.

## Các file

| File | Nội dung |
|---|---|
| `sha256_custom.py` | SHA-256 tự cài, menu nhập chuỗi, hiển thị các bước tính |
| `aes128.py` | AES-128, CBC, đệm PKCS#7, khóa = 16 byte đầu của SHA-256(họ tên chuẩn hóa), hiển thị các bước |
| `diffie_hellman.py` | Diffie–Hellman (Alice, Bob), nhóm 2048-bit RFC 3526 nhóm 14 hoặc p nhập tay, bảng bình phương liên tiếp |
| `elgamal_signature.py` | Chữ ký ElGamal, p nhập tay hoặc nhóm 2048-bit, hiển thị các bước (kể cả Euclid tính k⁻¹), nhập dữ liệu bị sửa, kiểm tra chữ ký (r, s) nhập tay |
| `number_theory.py` | Miller–Rabin, sinh số nguyên tố an toàn, Euclid mở rộng |
| `test_log.py` | Ghi mỗi lần thử vào `ket_qua_test.csv` |
| `run_cases.py`, `cases.txt` | Chạy hàng loạt các lần thử từ danh sách |
| `run_experiments.py` | Thực nghiệm đúng/sai và hiệu năng, ghi `results.json` |
| `ket_qua_mau.csv`, `results.json` | Kết quả mẫu, đo trên máy kiểm tra. Chạy lại để có số của máy bạn |

## Cách chạy

```
python sha256_custom.py
python aes128.py
python diffie_hellman.py
python elgamal_signature.py
python run_cases.py            # đọc cases.txt
python run_experiments.py      # mất khoảng 1–2 phút
python number_theory.py test
```

Mỗi chương trình tự chạy `self_test()` khi mở, rồi hiện menu: **1** giá trị gán sẵn (ví dụ tay), **2** nhập giá trị khác, **0** thoát. Có thể chạy nhiều lần liên tục trong cùng một phiên.

## Ghi kết quả nhiều lần thử

Mỗi lần thử trong các menu được ghi thêm vào `ket_qua_test.csv` (mở bằng Excel): STT, thời gian, chương trình, đầu vào, kết quả, đạt hay không. Cột **Đạt** để trống khi chương trình không có kỳ vọng sẵn.

## Chạy hàng loạt (`run_cases.py`)

Mỗi dòng của `cases.txt` là một lần thử, các phần cách nhau bằng `|` (cú pháp đầy đủ ở đầu file `run_cases.py`):

```
sha256     | chuỗi | [đầu digest mong đợi]
aes        | họ tên hoặc khóa hex | thông điệp | [IV hex]
aes-khoi   | khóa | khối 16 byte | [đầu bản mã mong đợi]
dh         | p g a b
elgamal    | p g x k H [H']        (k = - là ngẫu nhiên)
elgamal-tn | small hoặc big | thông điệp | [thông điệp bị sửa] | [x] | [k]
elgamal-kt | p g y H r s | [dung hoặc sai]
```

## Họ tên dùng sinh khóa AES

`aes128.py` chuẩn hóa họ tên: bỏ dấu, viết hoa, gộp khoảng trắng. "Nguyễn Lương Huynh" và "NGUYEN LUONG HUYNH" đều ra khóa `4955190b027604c857aaec2d7cb6f892`.

## Lưu ý

Với nhóm 2048-bit, `g = 2` sinh nhóm con bậc q = (p − 1)/2, không sinh toàn bộ Z_p*. Code chỉ dùng cho học tập: không chống tấn công đo thời gian, AES-CBC không xác thực, Diffie–Hellman không xác thực hai bên, và nhóm ElGamal nhỏ (ví dụ p = 467) không an toàn.
