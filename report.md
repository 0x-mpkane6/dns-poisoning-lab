# Runbook + Báo cáo thí nghiệm DNS OoB (Rl3)

---

## PHẦN 1 - CHẠY LAB OOB

### 1) Mục tiêu và phạm vi

- Lab này chỉ mô phỏng tấn công **Out-of-Bailiwick (OoB)** và phòng thủ **Rl3**.
- Không bao gồm mô phỏng Fragmentation/Rl2.
- Mục tiêu là so sánh 3 kịch bản:
  - Baseline (không tấn công)
  - Attack khi Defense OFF
  - Attack khi Defense ON

### 2) Khởi động lab lần đầu

Đi đến thư mục chứa `docker-compose.yml`:

```bash
cd Code
docker compose up -d --build
docker compose ps
```

Điều kiện pass:

- Thấy đủ 4 container `client`, `resolver`, `auth`, `attacker` ở trạng thái `Up`.

Nếu có container lỗi:

```bash
docker compose logs <tên_container>
```

### 3) Kịch bản A - Baseline (không có tấn công)

- Mục đích: xác nhận khi không có attacker thì resolver trả kết quả hợp lệ.
- Lệnh:

```bash
docker exec -it resolver bash /app/toggle_defense.sh off
docker compose stop attacker
docker exec -it client bash /app/test.sh example.net 10
cd scripts && ./measure.sh
```

- Tiêu chí pass/fail:
  - Pass: `bank.com` ra `203.0.113.80` trong `10/10` mẫu, `Poisoned = 0/10`, ASR = `0%`.
  - Fail: xuất hiện `6.6.6.6` trong baseline.

- Kết quả đo xác minh (09/04/2026):
  - Baseline: `10/10 -> 203.0.113.80`, `Poisoned = 0/10`, `ASR = 0.00%`.

### 4) Kịch bản B - Attack với Defense OFF

- Cần 2 terminal song song.

Terminal 1 (chạy attacker trước):

```bash
docker compose start attacker
docker exec -it attacker python3 /app/spoof.py
```

Terminal 2 (sau vài giây):

```bash
docker exec -it resolver bash /app/toggle_defense.sh off
docker exec -it client bash /app/test.sh example.net 50
cd scripts && ./measure.sh
```

- Lưu ý race timing:
  - Attacker phải chạy trước client trigger để có cửa sổ race.
  - Nếu ASR thấp bất thường (<20%), chạy lại với `100` rounds và đảm bảo attacker đang flood trước.

- Tiêu chí pass/fail:
  - Pass: có poisoning (`Poisoned > 0`) và ASR cao rõ rệt.
  - Fail: nhiều lần chạy liên tiếp mà `Poisoned = 0`, cần kiểm tra lại timing hoặc trạng thái attacker.

- Kết quả đo xác minh lại (3 lần, 50 rounds/lần):
  - Run 1: `40/50` poisoned (`80.00%`)
  - Run 2: `46/50` poisoned (`92.00%`)
  - Run 3: `49/50` poisoned (`98.00%`)
  - Trung bình: `45.00/50`, ASR `90.00%`

### 5) Kịch bản C - Reset cache và bật Defense ON

- Reset lab để tránh ảnh hưởng cache cũ:

```bash
cd scripts && ./reset.sh
```

- Bật Rl3:

```bash
docker exec -it resolver bash /app/toggle_defense.sh on
```

- Chạy lại attack giống kịch bản B:

Terminal 1:

```bash
docker compose start attacker
docker exec -it attacker python3 /app/spoof.py
```

Terminal 2:

```bash
docker exec -it client bash /app/test.sh example.net 50
cd scripts && ./measure.sh
```

- Tiêu chí pass/fail:
  - Pass: `Poisoned` về gần 0 (lý tưởng `0/50`) và ASR gần 0%.
  - Fail: vẫn thấy poisoning đáng kể khi defense ON.

- Kết quả đo xác minh lại (3 lần, 50 rounds/lần):
  - Run 1: `0/50` poisoned (`0.00%`)
  - Run 2: `0/50` poisoned (`0.00%`)
  - Run 3: `0/50` poisoned (`0.00%`)
  - Trung bình: `0.00/50`, ASR `0.00%`

### 6) Thu bằng chứng bằng tcpdump

Trong lúc attacker đang chạy, mở thêm 1 terminal:

```bash
docker exec -it resolver tcpdump -i eth0 -n -vv port 53 -c 5
```

- Lưu ý:
  - Attacker container có IP `10.10.0.200`, nhưng script spoof giả mạo source IP thành `10.10.0.100` (auth server).
  - Vì vậy trên resolver sẽ thấy packet nguồn `10.10.0.100 -> 10.10.0.53`.
  - Dùng `-vv` sẽ hiển thị chi tiết additional section để thấy trực tiếp OoB record.

---

## PHẦN 2 - BÁO CÁO HỌC THUẬT OOB

### 1) Cơ chế tấn công OoB

- Resolver hỏi authoritative server cho một tên miền trong zone `example.net`. Attacker chèn DNS response giả mạo, trong đó:
  - Answer section trả lời hợp lệ cho tên miền đang hỏi.
  - Additional section nhúng thêm record ngoài bailiwick: `bank.com -> 6.6.6.6`.

- Nếu resolver cache additional record mà không kiểm tra bailiwick, truy vấn `bank.com` sau đó sẽ bị trả về IP giả.
- Rl3 phòng thủ bằng cách chỉ chấp nhận record nằm trong phạm vi bailiwick của truy vấn; record ngoài phạm vi bị loại.

### 2) Cấu hình lab và điều kiện tái hiện

Topology:

- `client` `10.10.0.10`
- `resolver` `10.10.0.53`
- `auth` `10.10.0.100`
- `attacker` `10.10.0.200`

Thiết lập có chủ ý để tái hiện nhanh:

- Upstream source port cố định: `33333`
- TXID space giới hạn: `0..1023`
- Delay auth: `0.25s`
- Record hợp lệ đối chiếu:
  - `*.example.net -> 198.51.100.10`
  - `bank.com -> 203.0.113.80`
- Record giả attacker chèn:
  - `bank.com -> 6.6.6.6`

### 3) Kết quả thực nghiệm

- Dữ liệu tổng hợp (đo xác minh ngày **09/04/2026**):

| Scenario | Số lần chạy | Tổng mẫu | Poisoned | ASR |
|---------|-------------|----------|----------|-----|
| Baseline (OFF, không attacker) | 1 | 10 | 0 | 0.00% |
| Attack (Defense OFF) | 3 x 50 | 150 | 135 | 90.00% |
| Attack (Defense ON) | 3 x 50 | 150 | 0 | 0.00% |

- Chi tiết Attack OFF:

| Run | Total | Poisoned | ASR |
|-----|-------|----------|-----|
| 1 | 50 | 40 | 80.00% |
| 2 | 50 | 46 | 92.00% |
| 3 | 50 | 49 | 98.00% |

- Chi tiết Attack ON:

| Run | Total | Poisoned | ASR |
|-----|-------|----------|-----|
| 1 | 50 | 0 | 0.00% |
| 2 | 50 | 0 | 0.00% |
| 3 | 50 | 0 | 0.00% |

- Nhận xét:
  - Baseline sạch (`0%`) xác nhận hệ thống hoạt động đúng khi không có tấn công.
  - Khi OFF, ASR cao vì resolver cache record ngoài bailiwick trong additional section.
  - Khi ON, ASR về `0%` trong bộ mẫu đã đo, phù hợp kỳ vọng của Rl3.
  - ASR OFF dao động từ `80%` đến `98%` do race condition: auth delay tạo cửa sổ tấn công, nhưng lịch CPU/kernel scheduling và độ trễ stack mạng từng lần chạy vẫn khác nhau. Đây là đặc tính tự nhiên của tấn công thống kê, không phải lỗi mô hình.

### 4) Liên hệ paper và CVE

- Kết quả lab này **phù hợp** hướng bảo vệ của Rl3 trong paper Afek et al. (USENIX Security 2025): bailiwick check có thể chặn OoB poisoning hiệu quả. Tuy nhiên, dữ liệu trong repo chỉ là bộ mẫu trong môi trường mô phỏng nhỏ; vì vậy không nên viết thành "đã chứng minh đầy đủ zero FP/FN toàn diện trong mọi điều kiện".

- CVE có liên quan đến OoB cache poisoning có thể tham khảo:
  - CVE-2021-43105 (Technitium DNS)
  - CVE-2008-1454 (Microsoft DNS)

Trong báo cáo này, CVE được dùng để đặt bối cảnh, không phải kết quả benchmark trực tiếp trong repo.

### 5) Hạn chế

- Repo hiện tại chỉ mô phỏng OoB + Rl3, không có Fragmentation/Rl2.
- Lab cố ý làm yếu entropy (fixed source port `33333`, TXID space `0..1023`) để tái hiện nhanh.
- Trong môi trường thực tế, source port và TXID thường random mạnh hơn nên attacker cần nhiều packet và thời gian hơn; không nên suy diễn mức "dễ tấn công" ngoài lab.
- Chưa có benchmark trực tiếp với Suricata/Snort trong repo này.

### 6) Kết luận

Trong phạm vi lab hiện tại:

- OoB poisoning thành công cao khi tắt Rl3 (ASR trung bình `90.00%`).
- Bật Rl3 đưa ASR về `0.00%` trên bộ mẫu đã đo.

> Điều này cho thấy cơ chế bailiwick checking của Rl3 có hiệu quả rõ ràng đối với kịch bản OoB được mô phỏng.

## TCPDUMP `-vv` MẪU

Command:

```bash
docker exec -it resolver tcpdump -i eth0 -n -vv port 53 -c 5
```

Output:

```text
17:18:03.161499 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 122)
    10.10.0.100.53 > 10.10.0.53.33333: [udp sum ok] 316*- q: A? victim.example.net. 1/0/1 victim.example.net. A 198.51.100.10 ar: bank.com. A 6.6.6.6 (94)
17:18:03.162495 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 122)
    10.10.0.100.53 > 10.10.0.53.33333: [udp sum ok] 317*- q: A? victim.example.net. 1/0/1 victim.example.net. A 198.51.100.10 ar: bank.com. A 6.6.6.6 (94)
17:18:03.163507 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 122)
    10.10.0.100.53 > 10.10.0.53.33333: [udp sum ok] 318*- q: A? victim.example.net. 1/0/1 victim.example.net. A 198.51.100.10 ar: bank.com. A 6.6.6.6 (94)
17:18:03.164536 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 122)
    10.10.0.100.53 > 10.10.0.53.33333: [udp sum ok] 319*- q: A? victim.example.net. 1/0/1 victim.example.net. A 198.51.100.10 ar: bank.com. A 6.6.6.6 (94)
17:18:03.165550 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 122)
    10.10.0.100.53 > 10.10.0.53.33333: [udp sum ok] 320*- q: A? victim.example.net. 1/0/1 victim.example.net. A 198.51.100.10 ar: bank.com. A 6.6.6.6 (94)
```

- Giải thích:
  - TXID tăng tuần tự `316 -> 320` là dấu hiệu flood thử nhiều TXID liên tiếp.
  - Điều này quan trọng vì TXID space trong lab chỉ có `0..1023`; sau khoảng 1024 gói, attacker đã quét hết toàn bộ không gian TXID (về mặt TXID sẽ có gói khớp), nên kết quả tấn công phụ thuộc chủ yếu vào race timing với phản hồi thật từ auth server.
  - Trường `q: A? victim.example.net.` cho thấy truy vấn mục tiêu trong zone hợp lệ.
  - Trường `ar: bank.com. A 6.6.6.6` là bằng chứng trực tiếp OoB record bị nhét trong additional section.
  - Nguồn `10.10.0.100.53` là IP bị spoof từ attacker `10.10.0.200`.

## FILE CHÍNH LIÊN QUAN OOB

- `Code/resolver/resolver.py`
- `Code/resolver/toggle_defense.sh`
- `Code/auth/auth_server.py`
- `Code/attacker/scripts/spoof.py`
- `Code/client/test.sh`
- `Code/scripts/measure.sh`
