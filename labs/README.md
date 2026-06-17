# DNS Poisoning Labs (phạm vi Người 2)

Thư mục này bổ sung các lab cô lập cho phạm vi "Người 2", đồng thời giữ nguyên lab gốc ở thư mục root.

## Thư mục lab

- `oob/`: SOoB (Out-of-Bailiwick) + bật/tắt R3.
- `stype/`: S-type (TXID brute-force, port brute-force, Kaminsky) + bật/tắt R1.
- `sfrag/`: SFrag (IPID guessing) + bật/tắt R2.
- `bfrag/`: BFrag (bullseye IPID) + bật/tắt R2.
- `r2entropy/`: R2 cải tiến, ghi nhận frag2 và tính entropy IPID trước khi defend.
- `base/`: script dùng chung và quy ước chung.

## Giao diện runner thống nhất

Mỗi lab đều hỗ trợ:

```bash
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Ngoại lệ: `r2entropy/` tập trung chứng minh defense-on nên dùng:

```bash
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh benign-on 50
bash ./scripts/run_case.sh attack-on 50
```

Với `stype`, chọn biến thể bằng biến môi trường:

```bash
ATTACK_VARIANT=txid bash ./scripts/run_case.sh attack-off 50
ATTACK_VARIANT=port bash ./scripts/run_case.sh attack-off 50
ATTACK_VARIANT=kaminsky bash ./scripts/run_case.sh attack-off 50
```

Output metrics:

- ASR từ `/app/result.txt`
- Độ trễ avg/p95 từ `/app/latency_ms.txt` (chỉ tính RTT của target query)

## Quy trình khuyến nghị cho từng lab

```bash
cd <lab-folder>
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Lặp lại và lấy trung bình:

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Ghi chú

- Các file lab gốc ở thư mục root không bị thay đổi bởi cấu trúc này.
- Mỗi lab có subnet riêng để tránh chồng lấn docker network:
  - `oob`: `10.20.0.0/24`
  - `stype`: `10.50.0.0/24`
  - `sfrag`: `10.30.0.0/24`
  - `bfrag`: `10.40.0.0/24`
  - `r2entropy`: `10.60.0.0/24`
- Nếu Docker daemon đang tắt, `run_case.sh` sẽ thoát sớm với thông báo lỗi preflight.
