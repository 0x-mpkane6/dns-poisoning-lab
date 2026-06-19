# Quy ước labs/base

`labs/base` chứa các script dùng chung và các quy ước giao diện cho mọi biến thể lab.

## Script dùng chung

- `scripts/run_case_common.sh`: các hàm helper dùng bởi runner của từng lab.
- `scripts/measure_asr.sh`: tính ASR poisoning từ `/app/result.txt`.
- `scripts/measure_latency.sh`: tính độ trễ avg/p95 từ `/app/latency_ms.txt` (chỉ RTT của target query).
- `scripts/benchmark_case.sh`: chạy một case nhiều lần và in ra chỉ số trung bình.

## Chuẩn giao diện lab

Mỗi thư mục lab cần cung cấp:

- `./scripts/run_case.sh <baseline|attack-off|attack-on>[-weak|-full|-bruteforce] [rounds]`
- `./scripts/reset.sh`
- file output từ client:
  - `/app/result.txt` cho ASR
  - `/app/latency_ms.txt` cho mẫu độ trễ

`run_case.sh` thực hiện Docker preflight và dùng `docker compose up -d --build`.
Khi đổi entropy, runner mặc định force-recreate container để Docker Compose áp
dụng env mới. Đặt `BUILD_IMAGES=0` nếu muốn bỏ bước build cache.

## Biến môi trường dùng chung

- `DEFENSE_MODE` (`on|off`)
- `ENTROPY_MODE` (`full|weak|bruteforce`, mặc định `full`)
- `BUILD_IMAGES` (`1|0`, mặc định `1` trong runner)
- `TXID_SPACE`
- `TXID_SCAN_LIMIT`
- `UPSTREAM_FIXED_SRC_PORT` (`0` nghĩa là source port random)
- `RESOLVER_UPSTREAM_PORT`
- `SRC_PORT_START`
- `SRC_PORT_END`
- `SRC_PORT_SCAN_LIMIT`
- `PACKET_CHUNK_SIZE`
- `IPID_SPACE`
- `IPID_SCAN_LIMIT`
- `ATTACK_RATE`
- `ROUNDS`
- `POISON_IP`
