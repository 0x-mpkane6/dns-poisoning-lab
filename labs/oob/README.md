# Lab OoB (SOoB / R3)

Thư mục này là bản sao cô lập của lab OoB gốc, giữ nguyên logic tấn công và dùng chuẩn runner/output thống nhất cho toàn bộ các lab trong `labs/`.

## Nội dung bao phủ

- Họ tấn công: `SOoB` (Out-of-Bailiwick poisoning).
- Công tắc phòng thủ: bộ lọc bailiwick kiểu `R3` qua `toggle_defense.sh on|off`.
- Chỉ số đo:
  - ASR từ `result.txt`
  - mẫu độ trễ từ `latency_ms.txt` (chỉ RTT của target query)

## Chạy nhanh

Trong thư mục này:

```bash
docker info
```

Chạy các kịch bản:

```bash
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Benchmark tùy chọn (lặp 3 lần):

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Giao diện chuẩn

- Runner: `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- File kết quả trong client container: `/app/result.txt`
- File độ trễ trong client container: `/app/latency_ms.txt`

## Biến môi trường

- `DEFENSE_MODE` (`on|off`) chế độ khởi tạo cho resolver.
- `TXID_SPACE` kích thước không gian đoán TXID.
- `ATTACK_RATE` khoảng nghỉ giữa các vòng lặp tấn công.
- `ROUNDS` số vòng mặc định cho client probes.
- `POISON_IP` địa chỉ bị đầu độc được theo dõi trong chỉ số ASR.

## Xử lý sự cố

- Nếu ASR thấp bất thường ở `attack-off`, hãy tăng số rounds và đảm bảo attacker đang chạy (`docker compose logs attacker`).
- Nếu cần clean rebuild, chạy `bash ./scripts/reset.sh`.
