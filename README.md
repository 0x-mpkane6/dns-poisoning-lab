# DNS OoB Poisoning Lab (Controlled Resolver + Rl3 Defense)

Lab này tái hiện tấn công DNS cache poisoning theo hướng Out-of-Bailiwick (OoB), sau đó bật/tắt rule phòng thủ Rl3 để so sánh kết quả.

## 1) Topology

- `client` (`10.10.0.10`): gửi DNS query để kích hoạt resolver.
- `resolver` (`10.10.0.53`): resolver mô phỏng có cache và chế độ phòng thủ `Rl3` có thể bật/tắt.
- `auth` (`10.10.0.100`): authoritative DNS cho zone `example.net`.
- `attacker` (`10.10.0.200`): blind flood spoofed DNS response kèm additional OoB.

Network chung: `dnsnet` (`10.10.0.0/24`).

## 2) Chuẩn bị

```bash
docker compose up -d --build
```

Kiểm tra container:

```bash
docker compose ps
```

## 3) Test baseline (không có attacker)

Tắt defense:

```bash
docker exec -it resolver bash /app/toggle_defense.sh off
```

Trigger query:

```bash
docker exec -it client bash /app/test.sh example.net 10
```

Đo kết quả:

```bash
cd scripts
./measure.sh
```

Kỳ vọng baseline: `bank.com` ra IP thật (`203.0.113.80`), không bị `6.6.6.6`.

## 4) Chạy tấn công OoB (Defense OFF)

Terminal 1 (attacker):

```bash
docker exec -it attacker python3 /app/spoof.py
```

Terminal 2 (client trigger):

```bash
docker exec -it client bash /app/test.sh example.net 50
```

Đo kết quả:

```bash
cd scripts
./measure.sh
```

Kỳ vọng: tỉ lệ `6.6.6.6` cao khi defense OFF.

## 5) Bật Rl3 và test lại

Bật defense:

```bash
docker exec -it resolver bash /app/toggle_defense.sh on
```

Chạy lại attacker + trigger:

```bash
docker exec -it client bash /app/test.sh example.net 50
cd scripts
./measure.sh
```

Kỳ vọng: OoB records bị chặn, tỉ lệ poison giảm mạnh (về gần 0).

## 6) Reset lab

```bash
cd scripts
./reset.sh
```

## 7) File chính

Mô hình được cố ý thiết kế để tái hiện dễ dàng:

- Resolver forward query bằng source-port cố định `33333`.
- TXID chỉ nằm trong không gian nhỏ (`0..1023`).
- Attacker flood response giả mạo cho TXID range để thắng race.

- `resolver/resolver.py`: resolver có cache và logic Rl3.
- `resolver/toggle_defense.sh`: bật/tắt Rl3 (`on` / `off`).
- `auth/auth_server.py`: authoritative DNS server cho `example.net`.
- `attacker/scripts/spoof.py`: inject additional OoB (`bank.com -> 6.6.6.6`).
- `client/test.sh`: trigger query và ghi kết quả `bank.com`.
- `scripts/measure.sh`: tính tổng số mẫu và success rate poison.
