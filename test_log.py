"""Ghi lại kết quả mỗi lần thử vào file ket_qua_test.csv (mở được bằng Excel).

Các chương trình gọi log_result() sau mỗi lần chạy. File được tạo trong thư mục đang chạy lệnh,
và các lần thử mới luôn được nối thêm vào cuối file.
"""
import csv
import os
import time

LOG_FILE = "ket_qua_test.csv"


def log_result(program, inputs, outputs, ok=None):
    """Thêm một dòng vào CSV. Trả về số thứ tự (STT) của lần thử."""
    new_file = not os.path.exists(LOG_FILE)
    if new_file:
        stt = 1
    else:
        with open(LOG_FILE, newline="", encoding="utf-8-sig") as f:
            stt = sum(1 for _ in csv.reader(f))          # đã gồm dòng tiêu đề
    with open(LOG_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["STT", "Thời gian", "Chương trình", "Đầu vào", "Kết quả", "Đạt"])
        status = "" if ok is None else ("Đạt" if ok else "Không đạt")
        writer.writerow([stt, time.strftime("%Y-%m-%d %H:%M:%S"), program, inputs, outputs, status])
    return stt
