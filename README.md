# Triển khai 4 thuật toán mật mã bằng Python

## 1. Giới thiệu dự án

Dự án triển khai và kiểm thử 4 thuật toán mật mã bằng ngôn ngữ Python, bao gồm:

1. **SHA-256:** Hàm băm mật mã dùng để tạo giá trị băm có độ dài cố định 256 bit.
2. **AES-128:** Thuật toán mã hóa đối xứng sử dụng khóa 128 bit để mã hóa và giải mã dữ liệu.
3. **Diffie–Hellman:** Giao thức trao đổi khóa cho phép hai bên thiết lập khóa bí mật chung thông qua một kênh truyền không an toàn.
4. **Chữ ký số ElGamal:** Thuật toán chữ ký số sử dụng hệ mật mã khóa công khai để ký và xác minh tính hợp lệ của thông điệp.

Mục tiêu của dự án là tìm hiểu nguyên lý hoạt động, tự triển khai các phép toán nền tảng và kiểm tra tính chính xác của từng thuật toán thông qua các bộ dữ liệu kiểm thử và thực nghiệm.

### 1.1. Mục tiêu thực hiện

- Hiểu cấu trúc và nguyên lý hoạt động của từng thuật toán mật mã.
- Tự cài đặt các phép toán cần thiết thay vì phụ thuộc hoàn toàn vào thư viện có sẵn.
- Kiểm thử kết quả bằng các bộ dữ liệu tham chiếu và ví dụ cụ thể.
- Thực hiện các thử nghiệm với tham số nhỏ để dễ dàng kiểm tra bằng tay và tham số lớn để đánh giá khả năng xử lý.
- Ghi nhận kết quả thực nghiệm để phục vụ việc phân tích và so sánh.

### 1.2. Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ lập trình | Python |
| Kiểu dữ liệu | Integer, String, Bytes, List |
| Phép toán số học | Modular Arithmetic |
| Kiểm tra số nguyên tố | Miller–Rabin |
| Phép toán hỗ trợ | Euclidean Algorithm, Extended Euclidean Algorithm |
| Hàm băm | SHA-256 tự cài đặt |
| Quản lý kết quả | JSON |

**Lưu ý:** Các thuật toán mật mã và hàm băm trong dự án được tự cài đặt bằng Python. Không sử dụng thư viện mật mã có sẵn và không sử dụng `hashlib` để thay thế SHA-256 tự triển khai.

---

## 2. Cấu trúc thư mục

```text
Information_Security_Report_Source/
│
├── sha256_custom.py
├── aes128.py
├── diffie_hellman.py
├── elgamal_signature.py
├── number_theory.py
├── run_experiments.py
│
├── results.json
│
└── README.md
```

### 2.1. Mô tả chức năng từng file

| File | Chức năng |
|---|---|
| `sha256_custom.py` | Cài đặt thuật toán SHA-256 từ đầu, thực hiện tiền xử lý dữ liệu, chia khối, vòng lặp nén và tạo giá trị băm 256 bit. |
| `aes128.py` | Cài đặt AES-128 với chế độ CBC, hỗ trợ mã hóa, giải mã và đệm dữ liệu theo PKCS#7. |
| `diffie_hellman.py` | Triển khai giao thức Diffie–Hellman, tạo khóa riêng, tính khóa công khai và thiết lập khóa bí mật chung. |
| `elgamal_signature.py` | Triển khai thuật toán chữ ký số ElGamal, bao gồm quá trình tạo chữ ký và xác minh chữ ký. |
| `number_theory.py` | Cung cấp các phép toán số học phục vụ thuật toán mật mã, bao gồm lũy thừa modulo, Miller–Rabin, Euclid mở rộng và sinh số nguyên tố an toàn. |
| `run_experiments.py` | Thực hiện các thử nghiệm, tổng hợp số liệu và lưu kết quả vào file JSON. |
| `results.json` | Lưu kết quả thực nghiệm mẫu được tạo từ chương trình. |

### 2.2. Mối quan hệ giữa các file

Các file được tổ chức theo hướng tách biệt thuật toán chính và các phép toán hỗ trợ.

- `sha256_custom.py` cung cấp hàm băm SHA-256 cho những thành phần cần sử dụng.
- `number_theory.py` cung cấp các phép toán số học cho Diffie–Hellman, ElGamal và chương trình thực nghiệm.
- `aes128.py`, `diffie_hellman.py` và `elgamal_signature.py` chứa phần triển khai riêng của từng thuật toán.
- `run_experiments.py` sử dụng các thành phần trên để thực hiện và tổng hợp kết quả.

Đặc biệt, `elgamal_signature.py` sử dụng SHA-256 tự cài đặt để tạo giá trị băm của thông điệp, thay vì sử dụng `hashlib`.

---

## 3. Nội dung triển khai các thuật toán

### 3.1. SHA-256 – Hàm băm mật mã

**Mục đích:**

SHA-256 là thuật toán băm thuộc họ SHA-2. Thuật toán nhận đầu vào có độ dài bất kỳ và tạo ra giá trị băm cố định 256 bit (32 byte).

**Các bước triển khai:**

1. Tiền xử lý dữ liệu đầu vào:
   - Chuyển dữ liệu thành dạng bit.
   - Thêm bit `1` vào cuối thông điệp.
   - Thêm các bit `0` để độ dài đạt yêu cầu.
   - Bổ sung độ dài ban đầu của thông điệp vào cuối dữ liệu.

2. Chia dữ liệu thành các khối 512 bit.

3. Khởi tạo 8 giá trị băm ban đầu theo tiêu chuẩn SHA-256.

4. Thực hiện mở rộng thông điệp thành 64 từ 32 bit.

5. Thực hiện 64 vòng lặp nén trên mỗi khối dữ liệu bằng các phép toán:
   - XOR.
   - AND.
   - NOT.
   - Phép dịch phải.
   - Phép xoay phải.
   - Phép cộng modulo \(2^{32}\).

6. Kết hợp trạng thái cuối cùng để tạo ra giá trị băm 256 bit.

**Kiểm thử:**

Chương trình sử dụng 5 vector kiểm thử, bao gồm:

- Thông điệp rỗng.
- Chuỗi `"abc"`.
- Vector NIST có độ dài 448 bit.
- Dữ liệu họ tên.
- Một trường hợp kiểm thử bổ sung.

Các kết quả được đối chiếu với giá trị SHA-256 tham chiếu để kiểm tra tính chính xác.

### 3.2. AES-128 – Mã hóa đối xứng

**Mục đích:**

AES-128 là thuật toán mã hóa đối xứng, trong đó quá trình mã hóa và giải mã sử dụng cùng một khóa bí mật có độ dài 128 bit.

**Thông số triển khai:**

| Thông số | Giá trị |
|---|---|
| Độ dài khóa | 128 bit |
| Kích thước khối | 128 bit |
| Số vòng lặp | 10 vòng |
| Chế độ mã hóa | CBC |
| Padding | PKCS#7 |
| Độ dài khóa | 16 byte |

**Các bước mã hóa:**

1. Chuẩn hóa dữ liệu đầu vào.
2. Thực hiện đệm PKCS#7 để dữ liệu có độ dài phù hợp với kích thước khối 16 byte.
3. Chia dữ liệu thành các khối 128 bit.
4. Thực hiện mã hóa AES-128 trên từng khối theo chế độ CBC.
5. Kết hợp các khối đã mã hóa để tạo ciphertext.

Trong chế độ CBC, trước khi mã hóa một khối dữ liệu, khối đó được XOR với ciphertext của khối trước. Đối với khối đầu tiên, chương trình sử dụng IV (Initialization Vector).

**Các bước giải mã:**

1. Chia ciphertext thành các khối 128 bit.
2. Giải mã từng khối.
3. Thực hiện XOR với ciphertext của khối trước hoặc IV đối với khối đầu tiên.
4. Loại bỏ phần đệm PKCS#7.
5. Khôi phục dữ liệu ban đầu.

**Cách tạo khóa từ họ tên:**

Chương trình sử dụng họ tên làm dữ liệu đầu vào để tạo khóa AES-128.

Quy trình:

1. Loại bỏ dấu tiếng Việt.
2. Chuyển toàn bộ ký tự thành chữ hoa.
3. Gộp các khoảng trắng liên tiếp.
4. Tính SHA-256 trên chuỗi đã chuẩn hóa.
5. Lấy 16 byte đầu tiên của giá trị băm làm khóa AES-128.

Ví dụ:

```text
Nguyễn Lương Huynh
        |
Chuẩn hóa
        |
NGUYEN LUONG HUYNH
        |
SHA-256
        |
Lấy 16 byte đầu tiên
        |
4955190b027604c857aaec2d7cb6f892
```

**Kiểm thử:**

- Đối chiếu thuật toán AES-128 với FIPS-197, Phụ lục B và C.1.
- Kiểm thử chế độ CBC theo NIST SP 800-38A.
- Kiểm tra khả năng mã hóa và giải mã dữ liệu.
- Kiểm tra dữ liệu sau giải mã có khớp với dữ liệu ban đầu hay không.

### 3.3. Diffie–Hellman – Trao đổi khóa

**Mục đích:**

Diffie–Hellman là giao thức cho phép hai bên thiết lập một khóa bí mật chung thông qua kênh truyền công khai mà không cần trực tiếp truyền khóa bí mật cho nhau.

**Nguyên lý hoạt động:**

Hai bên thống nhất các tham số công khai:

- \(p\): Số nguyên tố.
- \(g\): Phần tử sinh hoặc phần tử được chọn trong nhóm con.

Sau đó:

**Bước 1: Tạo khóa riêng**

- Alice chọn số bí mật \(a\).
- Bob chọn số bí mật \(b\).

**Bước 2: Tính khóa công khai**

Alice tính:

\[
A=g^a \bmod p
\]

Bob tính:

\[
B=g^b \bmod p
\]

**Bước 3: Trao đổi khóa công khai**

Alice gửi \(A\) cho Bob và Bob gửi \(B\) cho Alice.

**Bước 4: Tính khóa bí mật chung**

Alice tính:

\[
K_A=B^a\bmod p
\]

Bob tính:

\[
K_B=A^b\bmod p
\]

Theo tính chất của phép toán modulo:

\[
K_A=K_B=g^{ab}\bmod p
\]

Như vậy, hai bên thu được cùng một khóa bí mật chung.

**Thông số triển khai:**

| Tham số | Giá trị |
|---|---|
| Nhóm chính | RFC 3526 – Group 14 |
| Kích thước số nguyên tố | 2048 bit |
| Nhóm so sánh | 1536 bit |
| Phần tử được chọn | \(g=2\) |
| Kiểm tra tham số | Miller–Rabin |
| Xử lý khóa chung | SHA-256 và lấy 16 byte |

Chương trình bổ sung hàm `derive_key()` để chuyển khóa bí mật chung thành khóa AES-128 bằng cách tính SHA-256 và lấy 16 byte đầu tiên.

Ngoài ra, chương trình kiểm tra khóa công khai có thuộc nhóm con bậc \(q=(p-1)/2\) hay không trước khi sử dụng.

### 3.4. ElGamal – Chữ ký số

**Mục đích:**

ElGamal Signature là thuật toán chữ ký số dựa trên bài toán logarithm rời rạc. Thuật toán sử dụng cặp khóa công khai và khóa bí mật để thực hiện ký và xác minh thông điệp.

**Các tham số:**

- \(p\): Số nguyên tố.
- \(g\): Phần tử được chọn trong nhóm.
- \(x\): Khóa bí mật.
- \(y\): Khóa công khai.

Khóa công khai được tính theo:

\[
y=g^x\bmod p
\]

**Quy trình tạo chữ ký:**

1. Tính giá trị băm SHA-256 của thông điệp.
2. Chuyển giá trị băm thành số nguyên \(H(m)\).
3. Chọn số ngẫu nhiên \(k\) thỏa mãn:

\[
1\leq k\leq p-2
\]

và:

\[
\gcd(k,p-1)=1
\]

4. Tính thành phần chữ ký thứ nhất:

\[
r=g^k\bmod p
\]

5. Tính nghịch đảo modulo của \(k\):

\[
k^{-1}\bmod(p-1)
\]

6. Tính thành phần chữ ký thứ hai:

\[
s=k^{-1}(H(m)-xr)\bmod(p-1)
\]

Chữ ký số thu được là cặp:

\[
(r,s)
\]

Nếu \(s=0\), chương trình lựa chọn lại \(k\) để tạo chữ ký hợp lệ.

**Quy trình xác minh chữ ký:**

Người nhận sử dụng thông điệp, chữ ký và khóa công khai để kiểm tra:

\[
g^{H(m)}\bmod p
=
y^r r^s\bmod p
\]

Nếu hai vế bằng nhau, chữ ký được xác minh là hợp lệ theo phép kiểm tra của thuật toán.

Nếu thông điệp bị thay đổi, giá trị băm sẽ thay đổi và quá trình xác minh thường trả về kết quả không hợp lệ.

**Thông số triển khai:**

| Trường hợp | Tham số |
|---|---|
| Ví dụ kiểm tra bằng tay | \(p=467\) |
| Nhóm lớn | 2048 bit |
| Hàm băm | SHA-256 tự cài đặt |
| Phép toán lũy thừa | `mod_pow` tự cài đặt |
| Nghịch đảo modulo | Extended Euclidean Algorithm |

Chương trình tách riêng hai hàm `sign_hash()` và `verify_hash()` để có thể kiểm tra trực tiếp bằng giá trị băm, đồng thời tái hiện ví dụ tính toán bằng tay với các tham số cụ thể.

---

## 4. Các thuật toán toán
