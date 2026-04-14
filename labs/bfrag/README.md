# Lab BFrag (Bullseye Fragment / R2)

Lab này mô phỏng `BFrag`, trong đó attacker đã biết trước IPID mục tiêu (bullseye mode) và lặp lại việc inject một mẫu frag2 giả mạo.

## Nội dung bao phủ

- Họ tấn công: `BFrag`.
- Công tắc phòng thủ: `R2` qua `toggle_defense.sh on|off`.
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
- Baseline profile dùng tên không kích hoạt, nên hành vi lành tính được tách khỏi luồng trigger tấn công.
- Auth server chạy ở `FRAG_MODE=bfrag` và phát `BULLSEYE_IPID`.
- Attacker gửi frag2 giả mạo với đúng `BULLSEYE_IPID` đó.
- Khi defense `on`, poisoning nên được giữ gần 0 bằng cách truncate luồng fragment đáng ngờ.
