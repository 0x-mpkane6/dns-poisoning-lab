# DNS OoB Poisoning Lab (Controlled Resolver + Rl3 Defense)

Lab này tái hiện tấn công DNS cache poisoning theo hướng Out-of-Bailiwick (OoB), sau đó bật/tắt rule phòng thủ Rl3 để so sánh kết quả.

## 1) Topology

- `client` (`10.10.0.10`): gửi DNS query để kích hoạt resolver.
- `resolver` (`10.10.0.53`): resolver mô phỏng có cache và chế độ phòng thủ `Rl3` có thể bật/tắt.
- `auth` (`10.10.0.100`): authoritative DNS cho zone `example.net`.
- `attacker` (`10.10.0.200`): blind flood spoofed DNS response kèm additional OoB.

Network chung: `dnsnet` (`10.10.0.0/24`).

## 2) Hướng dẫn chạy lab

Chạy toàn bộ lệnh tại thư mục gốc project:

```bash
cd d:/ATM/Project/Code
```

### Chạy tự động full pipeline

```bash
bash scripts/run_pipeline.sh
```

Tuỳ chọn:

```bash
# zone, baseline_rounds, attack_rounds
bash scripts/run_pipeline.sh example.net 10 50

# build lại image trước khi chạy
bash scripts/run_pipeline.sh --build example.net 10 50
```

### Bước 1: Khởi động môi trường

```bash
docker compose up -d --build
docker compose ps
```

### Bước 2: Baseline (không attacker, defense OFF)

```bash
docker exec -it resolver bash /app/toggle_defense.sh off
docker exec -it client bash /app/test.sh example.net 10
bash scripts/measure.sh
```

Kỳ vọng baseline: `bank.com` ra IP thật (`203.0.113.80`), không bị `6.6.6.6`.

### Bước 3: Tấn công OoB (defense OFF)

Terminal 1 (attacker):

```bash
docker exec -it attacker python3 /app/spoof.py
```

Terminal 2 (client trigger + đo):

```bash
docker exec -it client bash /app/test.sh example.net 50
bash scripts/measure.sh
```

Kỳ vọng: tỉ lệ `6.6.6.6` cao khi defense OFF.

### Bước 4: Bật Rl3 và test lại

```bash
docker exec -it resolver bash /app/toggle_defense.sh on
docker exec -it client bash /app/test.sh example.net 50
bash scripts/measure.sh
```

Kỳ vọng: OoB records bị chặn, tỉ lệ poison giảm mạnh (về gần 0).

### Bước 5: Reset lab (nếu cần chạy lại)

```bash
bash scripts/reset.sh
```

## 3) Cách đọc kết quả

Script đo nằm ở `scripts/measure.sh`, in ra:

- `Total`: số lần đo.
- `Poisoned`: số lần `bank.com` bị trúng `6.6.6.6`.
- `Success rate`: tỉ lệ poison theo phần trăm.

## 4) File chính

Mô hình được cố ý thiết kế để tái hiện dễ dàng:

- Mặc định resolver dùng source-port upstream random (`UPSTREAM_FIXED_SRC_PORT=0`)
  và TXID 16-bit (`TXID_SPACE=65536`).
- Muốn chạy demo yếu entropy cũ để thấy attack thắng race, đặt
  `ENTROPY_MODE=weak` hoặc `UPSTREAM_FIXED_SRC_PORT=33333 TXID_SPACE=1024`.
- Attacker flood response giả mạo cho TXID range cấu hình bằng
  `TXID_SCAN_LIMIT`.

- `resolver/resolver.py`: resolver có cache và logic Rl3.
- `resolver/toggle_defense.sh`: bật/tắt Rl3 (`on` / `off`).
- `auth/auth_server.py`: authoritative DNS server cho `example.net`.
- `attacker/scripts/spoof.py`: inject additional OoB (`bank.com -> 6.6.6.6`).
- `client/test.sh`: trigger query và ghi kết quả `bank.com`.
- `scripts/measure.sh`: tính tổng số mẫu và success rate poison.
- `scripts/reset.sh`: reset toàn bộ môi trường lab.
