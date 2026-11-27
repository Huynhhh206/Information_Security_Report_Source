# Bộ code 4 thuật toán mật mã (Python, tự cài đặt)

AES-128, Diffie–Hellman, SHA-256, chữ ký ElGamal. Không dùng thư viện mật mã và không dùng `hashlib`.

## Các file

| File | Nội dung |
|---|---|
| `sha256_custom.py` | SHA-256 tự cài, kiểm thử bằng 5 vector (rỗng, "abc", NIST 448 bit, họ tên, ...) |
| `aes128.py` | AES-128, chế độ CBC, đệm PKCS#7, khóa = 16 byte đầu của SHA-256(họ tên đã chuẩn hóa) |
| `diffie_hellman.py` | Diffie–Hellman, nhóm 2048-bit RFC 3526 nhóm 14 (và nhóm 1536-bit để so sánh) |
| `elgamal_signature.py` | Chữ ký ElGamal, nhóm nhỏ p = 467 (để kiểm tay) và nhóm 2048-bit |
| `number_theory.py` | Miller–Rabin, sinh số nguyên tố an toàn, Euclid mở rộng. `diffie_hellman.py` và `elgamal_signature.py` dùng `is_probable_prime` để kiểm tra p nhập tay; `run_experiments.py` dùng các hàm còn lại |
| `run_experiments.py` | Chạy các thực nghiệm, ghi `results.json` |
| `results.json` | Số liệu mẫu, đo trên máy kiểm tra. Chạy lại script để có số của máy bạn |

## Cách chạy

```
python sha256_custom.py
python aes128.py
python diffie_hellman.py
python elgamal_signature.py
python run_experiments.py      # mất khoảng 1–2 phút
python number_theory.py test   # kiểm thử số học
```

Mỗi file có hàm `self_test()` chạy tự động khi chạy file.

## Họ tên dùng sinh khóa AES

`aes128.py` tự chuẩn hóa họ tên: bỏ dấu, viết hoa, gộp khoảng trắng. Nhập "Nguyễn Lương Huynh" hay "NGUYEN LUONG HUYNH" đều ra khóa `4955190b027604c857aaec2d7cb6f892`.

## Những điểm đã sửa so với bản trước

- `elgamal_signature.py`: bỏ `hashlib` (dùng `sha256_custom`), dùng `mod_pow` tự cài thay cho `pow`, viết lại `extended_gcd` bằng vòng lặp (bản đệ quy báo `RecursionError` với modulo 2048 bit), chọn lại k khi s = 0, nhận tham số nhóm (p, g), tách `sign_hash` và `verify_hash` để tái hiện ví dụ tay (20, 17), demo sửa thông điệp không còn báo sai ngẫu nhiên khi p nhỏ.
- `diffie_hellman.py`: số nguyên tố trước đây ghi là nhóm 14 (2048 bit) nhưng thực chất là nhóm 5 (1536 bit); đã thay bằng nhóm 14 đúng chuẩn. Thêm kiểm tra khóa công khai thuộc nhóm con bậc q và hàm `derive_key` (SHA-256 của khóa chung, lấy 16 byte).
- `aes128.py`: thêm chuẩn hóa họ tên, và kiểm thử bằng FIPS-197 (Phụ lục B, C.1) và NIST SP 800-38A (CBC).
- `sha256_custom.py`: thêm vector NIST 448 bit và vector họ tên.

## Lưu ý

Với nhóm 2048-bit, `g = 2` sinh nhóm con bậc q = (p − 1)/2, không sinh toàn bộ Z_p*. Code chỉ dùng cho học tập: không chống tấn công đo thời gian, AES-CBC không xác thực, Diffie–Hellman không xác thực hai bên.
