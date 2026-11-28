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
- Cho phép dùng giá trị gán sẵn (chính là các ví dụ tính tay) hoặc nhập giá trị bất kỳ, và hiển thị từng bước tính để đối chiếu với bài tính tay.
- Ghi lại kết quả nhiều lần thử vào file CSV và cho phép chạy hàng loạt các lần thử từ một danh sách.
- Ghi nhận kết quả thực nghiệm để phục vụ việc phân tích và so sánh.

### 1.2. Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ lập trình | Python 3 (báo cáo sử dụng Python 3.14.6, chạy bằng terminal trên Windows 11) |
| Kiểu dữ liệu | Integer, String, Bytes, List |
| Phép toán số học | Modular Arithmetic |
| Kiểm tra số nguyên tố | Miller–Rabin |
| Phép toán hỗ trợ | Euclidean Algorithm, Extended Euclidean Algorithm |
| Hàm băm | SHA-256 tự cài đặt |
| Số ngẫu nhiên | Module `secrets` của thư viện chuẩn |
| Quản lý kết quả | JSON (`results.json`) và CSV (`ket_qua_test.csv`) |

**Lưu ý:** Các thuật toán mật mã và hàm băm trong dự án được tự cài đặt bằng Python. Không sử dụng thư viện mật mã có sẵn và không sử dụng `hashlib` để thay thế SHA-256 tự triển khai. Chỉ sử dụng thư viện chuẩn của Python cho các việc phụ trợ: `struct`, `time`, `secrets`, `unicodedata`, `math`, `random`, `sys`, `typing`, `json`, `platform`, `csv`, `os`.

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
│
├── test_log.py
├── run_cases.py
├── cases.txt
├── run_experiments.py
│
├── results.json
├── ket_qua_mau.csv
├── ket_qua_test.csv        (được tạo ra khi chạy các chương trình)
│
└── README.md
```

### 2.1. Mô tả chức năng từng file

| File | Chức năng |
|---|---|
| `sha256_custom.py` | Cài đặt SHA-256 từ đầu: tiền xử lý dữ liệu, chia khối, mở rộng thông điệp, 64 vòng nén và tạo giá trị băm 256 bit. Có menu nhập chuỗi tùy ý, hiển thị các bước tính và đo tốc độ. |
| `aes128.py` | Cài đặt AES-128 với chế độ CBC, mã hóa, giải mã và đệm PKCS#7. Khóa là 16 byte đầu của SHA-256(họ tên đã chuẩn hóa). Có menu nhập họ tên, thông điệp và IV, hiển thị các bước (mở rộng khóa, từng vòng mã hóa và giải mã). |
| `diffie_hellman.py` | Triển khai Diffie–Hellman giữa Alice và Bob: tạo khóa riêng, tính khóa công khai, kiểm tra khóa công khai và thiết lập khóa chung. Dùng nhóm 2048 bit (RFC 3526, nhóm 14) hoặc p do người dùng nhập. Có bảng bình phương liên tiếp cho các phép lũy thừa. |
| `elgamal_signature.py` | Triển khai chữ ký số ElGamal: tạo khóa, ký, xác minh. Dùng p nhập tay hoặc nhóm 2048 bit. Hiển thị các bước (kể cả Euclid mở rộng tính \(k^{-1}\) và bảng bình phương liên tiếp), cho nhập thông điệp hoặc H' bị sửa, và kiểm tra chữ ký \((r,s)\) do người dùng nhập. |
| `number_theory.py` | Cung cấp các phép toán số học: lũy thừa modulo, Euclid mở rộng, nghịch đảo modulo, Miller–Rabin, sinh số nguyên tố và số nguyên tố an toàn, tìm phần tử sinh. |
| `test_log.py` | Hàm `log_result()` ghi mỗi lần thử vào `ket_qua_test.csv`. |
| `run_cases.py`, `cases.txt` | Chạy hàng loạt các lần thử đọc từ danh sách trong `cases.txt` rồi ghi kết quả vào `ket_qua_test.csv`. |
| `run_experiments.py` | Thực hiện các thử nghiệm đúng/sai và đo hiệu năng, tổng hợp số liệu và lưu vào `results.json`. |
| `results.json`, `ket_qua_mau.csv` | Kết quả mẫu, đo trên máy kiểm tra, dùng để tham khảo định dạng. Cần chạy lại trên máy của mình để có số liệu của máy đó. |
| `ket_qua_test.csv` | Kết quả các lần thử của chính bạn, tự được tạo và nối thêm mỗi lần chạy. |

### 2.2. Mối quan hệ giữa các file

Các file được tổ chức theo hướng tách biệt thuật toán chính và các phép toán hỗ trợ.

- `sha256_custom.py` cung cấp hàm băm SHA-256, được `aes128.py` (tạo khóa từ họ tên), `diffie_hellman.py` (suy ra khóa AES từ khóa chung) và `elgamal_signature.py` (băm thông điệp trước khi ký) sử dụng.
- `diffie_hellman.py` cung cấp `mod_pow` và các hàm nhập liệu, được `elgamal_signature.py` dùng lại.
- `number_theory.py` cung cấp phép kiểm tra nguyên tố Miller–Rabin (`is_probable_prime`) cho `diffie_hellman.py` và `elgamal_signature.py` để từ chối p không phải số nguyên tố, cùng việc sinh số nguyên tố an toàn và tìm phần tử sinh cho `run_experiments.py`.
- `test_log.py` được `sha256_custom.py`, `aes128.py`, `diffie_hellman.py`, `elgamal_signature.py` và `run_cases.py` dùng để ghi kết quả.
- `run_cases.py` gọi trực tiếp các hàm của bốn thuật toán để chạy các lần thử trong `cases.txt`.
- `run_experiments.py` sử dụng bốn thuật toán và `number_theory.py` để thực hiện và tổng hợp kết quả.

Đặc biệt, `elgamal_signature.py` sử dụng SHA-256 tự cài đặt để tạo giá trị băm của thông điệp, thay vì sử dụng `hashlib`.

---

## 3. Nội dung triển khai các thuật toán

Mỗi chương trình tự chạy `self_test()` khi mở. Nếu có lỗi, chương trình dừng ngay; nếu đạt, in dòng `[PASS]`. Sau đó chương trình hiện menu:

- **1:** dùng giá trị gán sẵn (ví dụ tính tay).
- **2:** nhập giá trị khác.
- **0:** thoát.

Chương trình chạy liên tục nhiều lần trong cùng một phiên cho đến khi chọn 0. Với `sha256_custom.py` có thêm lựa chọn **3** (đo tốc độ), với `elgamal_signature.py` có thêm lựa chọn **3** (kiểm tra chữ ký do bạn nhập). Sau mỗi lần thử, kết quả được ghi vào `ket_qua_test.csv` (xem mục 6).

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

**Giao diện chương trình (`python sha256_custom.py`):**

- Lựa chọn 1 băm chuỗi gán sẵn `NGUYEN LUONG HUYNH`, lựa chọn 2 băm chuỗi do người dùng nhập, lựa chọn 3 đo tốc độ.
- Có thể chọn **hiển thị các bước tính**: đệm dữ liệu, 16 từ \(W_0 \dots W_{15}\), mở rộng \(W_{16} \dots W_{63}\), giá trị khởi tạo của 8 biến, từng vòng nén (\(\Sigma_1, Ch, T_1, \Sigma_0, Maj, T_2\) và 8 biến mới) và bước cộng cuối. Người dùng chọn số khối và số vòng muốn in. Kết quả in từng bước được so sánh với hàm `sha256()` để bảo đảm hai đường tính cho cùng kết quả.

**Kiểm thử:**

Chương trình sử dụng 5 vector kiểm thử, bao gồm:

- Thông điệp rỗng.
- Chuỗi `"abc"`.
- Chuỗi `"hello"`.
- Vector NIST có độ dài 448 bit.
- Dữ liệu họ tên `NGUYEN LUONG HUYNH`.

Các kết quả được đối chiếu với giá trị SHA-256 tham chiếu để kiểm tra tính chính xác. Các thử nghiệm bổ sung (một triệu chữ `a`, hiệu ứng thác đổ) nằm trong `run_experiments.py`.

### 3.2. AES-128 – Mã hóa đối xứng

**Mục đích:**

AES-128 là thuật toán mã hóa đối xứng, trong đó quá trình mã hóa và giải mã sử dụng cùng một khóa bí mật có độ dài 128 bit.

**Thông số triển khai:**

| Thông số | Giá trị |
|---|---|
| Độ dài khóa | 128 bit (16 byte) |
| Kích thước khối | 128 bit |
| Số vòng lặp | 10 vòng |
| Chế độ mã hóa | CBC |
| Padding | PKCS#7 |
| IV | 16 byte, ngẫu nhiên bằng `secrets` hoặc do người dùng nhập (32 chữ số hex) |

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

Do có bước chuẩn hóa, "Nguyễn Lương Huynh", "nguyen luong huynh" và "NGUYEN LUONG HUYNH" đều cho cùng một khóa.

**Giao diện chương trình (`python aes128.py`):**

- Lựa chọn 1 dùng họ tên `Nguyễn Lương Huynh` và bản rõ `UNOFTRANSPORTHCM` với IV toàn số 0, nên khối đầu tiên trùng với ví dụ tính tay (bản rõ XOR IV chính là bản rõ).
- Lựa chọn 2 cho nhập họ tên, thông điệp và IV (Enter = IV ngẫu nhiên).
- Có thể chọn **hiển thị các bước tính**: 11 khóa vòng (kèm RotWord, SubWord, Rcon), ma trận trạng thái sau từng phép biến đổi của từng vòng khi mã hóa và khi giải mã, và phép XOR của CBC. Người dùng chọn số khối muốn in chi tiết.
- Sau khi mã hóa, chương trình giải mã lại và kiểm tra kết quả trùng với bản rõ ban đầu.

**Kiểm thử:**

- Đối chiếu thuật toán AES-128 với FIPS-197, Phụ lục B và C.1.
- Kiểm thử chế độ CBC theo NIST SP 800-38A.
- Kiểm tra khả năng mã hóa và giải mã dữ liệu nhiều độ dài.
- Kiểm tra khóa sinh từ họ tên có và không có dấu.
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
| Phần tử được chọn | \(g=2\) (sinh nhóm con bậc \(q=(p-1)/2\)) |
| Ví dụ tính tay | \(p=23,\ g=5,\ a=6,\ b=15\) cho \(A=8,\ B=19,\ K=2\) |
| Kiểm tra tham số | Miller–Rabin (p nhập tay phải là số nguyên tố) |
| Xử lý khóa chung | SHA-256 và lấy 16 byte |

Chương trình bổ sung hàm `derive_key()` để chuyển khóa bí mật chung thành khóa AES-128 bằng cách tính SHA-256 và lấy 16 byte đầu tiên.

Ngoài ra, chương trình kiểm tra khóa công khai có thuộc nhóm con bậc \(q=(p-1)/2\) hay không trước khi sử dụng.

**Giao diện chương trình (`python diffie_hellman.py`):**

- Lựa chọn 1 dùng ví dụ tay \(p=23,\ g=5,\ a=6,\ b=15\).
- Lựa chọn 2 cho nhập \(p\) (Enter = nhóm 2048 bit), \(g\), \(a\), \(b\) (Enter = chọn ngẫu nhiên). Số \(p\) không phải số nguyên tố bị từ chối bằng Miller–Rabin. Các số \(g,a,b\) phải nằm trong khoảng \(2 \dots p-2\).
- Có thể chọn **hiển thị các bước tính**: bảng bình phương liên tiếp cho \(g^a,\ g^b,\ B^a,\ A^b\) (đọc số mũ từ bit thấp lên cao, đúng như hàm `mod_pow`) và bậc của \(g\) khi \(p\) không quá lớn. Với số lớn hơn 64 bit, chương trình in rút gọn, trừ khi chọn in đầy đủ.

**Kiểm thử:**

- Ví dụ \(p=23\) cho \(A=8,\ B=19,\ K=2\).
- Các khóa công khai không hợp lệ (\(0,\ 1,\ p-1,\ p\)) bị từ chối.
- Nhóm 2048 bit: \(g=2\) có bậc \(q\), hai bên ra cùng khóa chung và cùng khóa AES.

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
2. Chuyển giá trị băm thành số nguyên \(H(m)\) (lấy modulo \(p-1\)).
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

Người nhận sử dụng thông điệp, chữ ký và khóa công khai để kiểm tra \(0<r<p\), \(0<s<p-1\) và:

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
| Ví dụ tính tay | \(p=23,\ g=5,\ x=6,\ k=5,\ H=7\) cho chữ ký \((20,17)\) |
| Nhóm nhỏ dùng để kiểm thử và thực nghiệm | \(p=467,\ g=2\) |
| Nhóm lớn | 2048 bit (RFC 3526, nhóm 14) |
| Hàm băm | SHA-256 tự cài đặt |
| Phép toán lũy thừa | `mod_pow` tự cài đặt |
| Nghịch đảo modulo | Extended Euclidean Algorithm |

Chương trình tách riêng hai hàm `sign_hash()` và `verify_hash()` để có thể kiểm tra trực tiếp bằng giá trị băm, đồng thời tái hiện ví dụ tính toán bằng tay với các tham số cụ thể.

**Giao diện chương trình (`python elgamal_signature.py`):**

- Lựa chọn 1 dùng ví dụ tay \(p=23,\ g=5,\ x=6,\ H=7,\ k=5\).
- Lựa chọn 2 cho nhập \(p\) (số nguyên tố, Enter = nhóm 2048 bit), \(g\), khóa bí mật \(x\) (Enter = ngẫu nhiên), dữ liệu cần ký (thông điệp văn bản hoặc nhập trực tiếp giá trị băm \(H\)) và \(k\) (Enter = ngẫu nhiên).
- Người dùng có thể **tự nhập thông điệp hoặc H' bị sửa** để kiểm tra chữ ký cũ. Nhấn Enter thì chương trình tự sửa như trước (thêm dấu `!` hoặc \(H+1\)).
- Có thể chọn **hiển thị các bước tính**: bảng bình phương liên tiếp cho \(y,\ r,\ g^H,\ y^r,\ r^s\) và các bước Euclid mở rộng tính \(k^{-1}\).
- Sau mỗi lần ký, chương trình hỏi có ký lại cùng dữ liệu với \(k\) khác (giữ nguyên \(p,\ g,\ x\)) hay không.
- Lựa chọn 3 kiểm tra một chữ ký \((r,s)\) do người dùng nhập, với \(p,\ g\), khóa công khai \(y\) và dữ liệu (thông điệp hoặc \(H\)).

**Kiểm thử:**

- Ví dụ tay cho chữ ký \((20,17)\), và \(H\) đổi thành 8 thì bị từ chối.
- Nhóm \(p=467\): 300 chữ ký đúng đều được chấp nhận, \(r\) hoặc \(s\) bằng 0 bị từ chối.
- Nhóm 2048 bit: ký, xác minh đúng và phát hiện thông điệp bị sửa.

---

## 4. Các thuật toán toán học hỗ trợ

Các phép toán nền tảng nằm trong `number_theory.py`:

| Hàm | Chức năng |
|---|---|
| `mod_exp(base, exp, mod)` | Lũy thừa modulo bằng phương pháp bình phương liên tiếp. |
| `egcd(a, b)` | Euclid mở rộng, trả về \((g,x,y)\) sao cho \(ax+by=\gcd(a,b)\). |
| `mod_inv(a, m)` | Nghịch đảo modulo; báo lỗi khi \(\gcd(a,m)\neq 1\). |
| `is_probable_prime(n)` | Kiểm tra nguyên tố bằng Miller–Rabin. |
| `generate_prime(bits)` | Sinh số nguyên tố ngẫu nhiên có đúng `bits` bit. |
| `generate_safe_prime(bits)` | Sinh số nguyên tố an toàn \(p=2q+1\) với cả \(p\) và \(q\) nguyên tố. |
| `find_generator(p, q)` | Tìm phần tử sinh của nhóm \(\mathbb{Z}_p^*\) khi \(p=2q+1\). |

Cách chạy:

```text
python number_theory.py            # menu: nghịch đảo modulo / Miller–Rabin (có hiển thị bước), chọn 0 hoặc gõ q để thoát
python number_theory.py test       # chạy các bộ kiểm thử tự động
python number_theory.py gen 256    # sinh số nguyên tố an toàn 256 bit và một phần tử sinh
```

---

## 5. Cách chạy

```text
python sha256_custom.py
python aes128.py
python diffie_hellman.py
python elgamal_signature.py
python run_cases.py            # đọc cases.txt
python run_experiments.py      # mất khoảng 1–2 phút
python number_theory.py test
```

Các chương trình cần chạy trong thư mục chứa các file `.py` (các file import lẫn nhau). File `ket_qua_test.csv` được tạo trong thư mục đang chạy lệnh.

---

## 6. Ghi kết quả nhiều lần thử

Mỗi lần thử trong các menu được ghi thêm vào `ket_qua_test.csv` (mở bằng Excel). File dùng mã hóa UTF-8 có BOM để Excel hiển thị đúng tiếng Việt. Các cột:

| Cột | Ý nghĩa |
|---|---|
| STT | Số thứ tự lần thử |
| Thời gian | Thời điểm ghi |
| Chương trình | SHA-256, AES-128 CBC, Diffie-Hellman, ElGamal ký… |
| Đầu vào | Các giá trị đã nhập hoặc đã chọn |
| Kết quả | Kết quả chương trình tính được |
| Đạt | `Đạt` hoặc `Không đạt`; để trống khi chương trình không có kỳ vọng sẵn |

Các lần thử mới luôn được nối vào cuối file, không ghi đè.

---

## 7. Chạy hàng loạt (`run_cases.py`)

Thay vì nhập tay từng lần, ghi các lần thử vào `cases.txt` rồi chạy `python run_cases.py` (hoặc `python run_cases.py ten_file_khac.txt`). Mỗi dòng là một lần thử, các phần cách nhau bằng dấu `|`; dòng trống hoặc bắt đầu bằng `#` bị bỏ qua.

```text
sha256     | chuỗi | [đầu digest mong đợi]
aes        | họ tên hoặc khóa hex | thông điệp | [IV hex]
aes-khoi   | khóa | khối 16 byte | [đầu bản mã mong đợi]
dh         | p g a b
elgamal    | p g x k H [H']                    (k = - là ngẫu nhiên)
elgamal-tn | small hoặc big | thông điệp | [thông điệp bị sửa] | [x] | [k]
elgamal-kt | p g y H r s | [dung hoặc sai]
```

Dòng có ghi kết quả mong đợi thì chương trình tự đối chiếu và ghi `Đạt` hoặc `Không đạt`. Một số dòng trong `cases.txt` được cố ý đặt sai (ví dụ \(p\) là hợp số, hoặc \(k\) không nguyên tố cùng nhau với \(p-1\)) để xem chương trình báo lỗi như thế nào, nên có lần thử ghi `Không đạt` là bình thường.

---

## 8. Thực nghiệm (`run_experiments.py`)

Chương trình chạy toàn bộ các thử nghiệm đúng/sai và đo hiệu năng rồi lưu vào `results.json` (UTF-8):

| Thuật toán | Nội dung thực nghiệm |
|---|---|
| SHA-256 | Các vector chuẩn, một triệu chữ `a`, hiệu ứng thác đổ (đổi 1 bit), tốc độ theo độ dài dữ liệu. |
| AES-128 | Hai ví dụ FIPS-197, CBC mã hóa rồi giải mã nhiều độ dài, tốc độ mã hóa và giải mã. |
| Diffie–Hellman | Ví dụ \(p=23\), 30 lần trao đổi ở nhóm 2048 bit, Miller–Rabin cho \(p\) và \((p-1)/2\), thời gian theo kích thước \(p\) (256, 512, 1536, 2048 bit), tấn công vét cạn \(p\) 16–28 bit, tấn công xen giữa khi không xác thực. |
| ElGamal | Ví dụ tay, 200 chữ ký ở nhóm 2048 bit, tỉ lệ chấp nhận nhầm thông điệp bị sửa ở \(p=467\), thời gian ký và kiểm tra theo kích thước \(p\), tấn công khi dùng lại \(k\). |

Thời gian chạy phụ thuộc vào máy, nên chỉ nên so sánh tương đối. `results.json` và `ket_qua_mau.csv` đi kèm là số đo trên máy kiểm tra; hãy chạy lại để có số liệu của máy mình.

---

## 9. Lưu ý và hạn chế

- Với nhóm 2048 bit, \(g=2\) sinh nhóm con bậc \(q=(p-1)/2\), không sinh toàn bộ \(\mathbb{Z}_p^*\).
- Mã nguồn chỉ dùng cho học tập, không dùng trong hệ thống thật: không chống tấn công đo thời gian (side-channel), AES-CBC không xác thực dữ liệu, Diffie–Hellman không xác thực hai bên, và nhóm ElGamal nhỏ (ví dụ \(p=467\)) không an toàn.
- Khóa AES được sinh từ họ tên đã chuẩn hóa (bỏ dấu, viết hoa, gộp khoảng trắng). Nếu băm nguyên chuỗi có dấu thì sẽ ra khóa khác.
- Tốc độ thấp là do mã nguồn Python thuần, không so sánh được với thư viện tối ưu.
