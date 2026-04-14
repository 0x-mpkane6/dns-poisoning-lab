# Quy ước labs/base

`labs/base` chứa các script dùng chung và các quy ước giao diện cho mọi biến thể lab.

## Script dùng chung

- `scripts/run_case_common.sh`: các hàm helper dùng bởi runner của từng lab.
- `scripts/measure_asr.sh`: tính ASR poisoning từ `/app/result.txt`.
- `scripts/measure_latency.sh`: tính độ trễ avg/p95 từ `/app/latency_ms.txt` (chỉ RTT của target query).
- `scripts/benchmark_case.sh`: chạy một case nhiều lần và in ra chỉ số trung bình.

## Chuẩn giao diện lab

Mỗi thư mục lab cần cung cấp:

- `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- `./scripts/reset.sh`
- file output từ client:
  - `/app/result.txt` cho ASR
  - `/app/latency_ms.txt` cho mẫu độ trễ

`run_case.sh` thực hiện Docker preflight và dùng `docker compose up -d` (không ép rebuild).
Dùng `./scripts/reset.sh` khi cần clean rebuild.

## Biến môi trường dùng chung

- `DEFENSE_MODE` (`on|off`)
- `TXID_SPACE`
- `IPID_SPACE`
- `ATTACK_RATE`
- `ROUNDS`
- `POISON_IP`
