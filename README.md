# DNS Cache Poisoning Lab (Docker)

## 1. Giới thiệu

Lab này được xây dựng nhằm mô phỏng và nghiên cứu **tấn công DNS Cache Poisoning** và các cơ chế phòng thủ liên quan.

Hệ thống sử dụng Docker để giả lập một môi trường mạng gồm:

* Client gửi truy vấn DNS
* Resolver (máy chủ DNS trung gian – mục tiêu tấn công)
* Authoritative DNS (máy chủ DNS thật)
* Attacker thực hiện giả mạo phản hồi DNS

### Mục tiêu:

* Hiểu quy trình phân giải DNS
* Thực hiện tấn công cache poisoning
* Bật/tắt cơ chế phòng thủ và so sánh hiệu quả
* Đo tỉ lệ thành công của tấn công

---

## 2. Sơ đồ hoạt động

```
        +-------------+
        |   Client    |
        +-------------+
               |
               v
        +-------------+
        |  Resolver   |  <-- Mục tiêu bị tấn công
        +-------------+
               |
        +------+------+
        |             |
        v             v
+-------------+   +-------------+
|   Attacker  |   |    Auth     |
+-------------+   +-------------+
```

### IP các thành phần

| Thành phần | IP          |
| ---------- | ----------- |
| Client     | 10.10.0.10  |
| Resolver   | 10.10.0.53  |
| Auth DNS   | 10.10.0.100 |
| Attacker   | 10.10.0.200 |

---

## 3. Cấu trúc thư mục

```
dns-poisoning-lab/
│
├── client/
│   ├── Dockerfile      # Cài đặt môi trường client
│   └── test.sh         # Script gửi nhiều DNS query
│
├── resolver/
│   ├── Dockerfile      # Chạy Unbound DNS
│   ├── unbound.conf    # Cấu hình DNS
│   └── toggle_defense.sh  # Bật/tắt cơ chế phòng thủ
│
├── auth/
│   └── Dockerfile      # DNS server thật (Bind9)
│
├── attacker/
│   ├── Dockerfile      # Môi trường tấn công (Kali + Scapy)
│   └── scripts/
│       └── spoof.py    # Script giả mạo DNS response
│
├── scripts/
│   ├── reset.sh        # Reset toàn bộ lab
│   └── measure.sh      # Tính tỉ lệ poisoning
│
└── docker-compose.yml  # Cấu hình toàn bộ hệ thống
```

---

## 4. Mô tả các thành phần

### 4.1 Client

* Sử dụng `dig` để gửi DNS query
* Script `test.sh` gửi nhiều request để tăng xác suất bị tấn công

---

### 4.2 Resolver (Target)

* Sử dụng **Unbound DNS**
* Có chức năng cache
* Là mục tiêu chính của tấn công cache poisoning

---

### 4.3 Authoritative DNS

* Mô phỏng DNS server thật
* Trả về IP hợp lệ

---

### 4.4 Attacker

* Sử dụng **Scapy**
* Gửi các gói DNS giả mạo nhằm đầu độc cache

---

## 5. Công cụ đã cài sẵn

| Thành phần | Công cụ                 |
| ---------- | ----------------------- |
| Client     | dig (dnsutils)          |
| Resolver   | unbound                 |
| Attacker   | python3, scapy, tcpdump |

---

## 6. Cách chạy lab

### 6.1 Build và khởi động

```bash
docker-compose up -d --build
```

---

### 6.2 Kiểm tra hoạt động

```bash
docker exec -it client dig @10.10.0.53 example.com
```

---

## 7. Tấn công demo 

### Bước 1: chạy attacker

```bash
docker exec -it attacker python3 /app/spoof.py
```

---

### Bước 2: gửi nhiều query

```bash
docker exec -it client bash /app/test.sh
```

---

### Bước 3: đo kết quả

```bash
cd scripts
./measure.sh
```

---

## 8. Bật / tắt cơ chế phòng thủ

### Tắt defense

```bash
docker exec -it resolver bash /toggle_defense.sh off
```

---

### Bật defense

```bash
docker exec -it resolver bash /toggle_defense.sh on
```

---

## 9. Reset lab

```bash
docker-compose down -v
docker-compose up -d --build
```

---

## 10. Kết quả mong đợi

| Trạng thái  | Kết quả                  |
| ----------- | ------------------------ |
| Defense OFF | Tỉ lệ tấn công cao hơn   |
| Defense ON  | Tỉ lệ tấn công giảm mạnh |

---

## 11. Lưu ý

* Cần reset cache giữa các lần test
* Tấn công phụ thuộc vào:

  * TXID
  * Port
  * Timing

---
