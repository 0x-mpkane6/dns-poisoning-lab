# Lab SFrag (Fragment Guessing / R2)

Lab này mô phỏng họ `SFrag`, nơi attacker đoán IPID để đưa dữ liệu second-fragment giả mạo.

## Nội dung bao phủ

- Họ tấn công: `SFrag`.
- Công tắc phòng thủ: xử lý fragmentation kiểu `R2` qua `toggle_defense.sh on|off`.
- Chỉ số đo:
  - ASR từ `/app/result.txt`
  - độ trễ từ `/app/latency_ms.txt` (chỉ RTT của target query)

## Chạy nhanh

```bash
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

## Giao diện chuẩn

- Runner: `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- Biến dùng chung: `DEFENSE_MODE`, `TXID_SPACE`, `IPID_SPACE`, `ATTACK_RATE`, `ROUNDS`, `POISON_IP`

## Ghi chú

- Fragment marker (`FRAG1`) chỉ được gắn cho query name thuộc attack-profile (tiền tố `frag*`).
- Baseline profile dùng tên không kích hoạt, nên hành vi lành tính thông thường được tách khỏi luồng trigger tấn công.
- `attack-off`: resolver merge payload frag2 giả mạo khi IPID khớp.
- `attack-on`: resolver phát hiện luồng frag và trả response truncated (`TC=1`) thay vì cache dữ liệu giả mạo.
- Nếu tỉ lệ poisoning quá thấp, hãy tăng `ROUNDS` và giảm `ATTACK_RATE`.
