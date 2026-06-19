# DNS Poisoning Labs (phạm vi Người 2)

Thư mục này chứa các lab cô lập cho phần việc của Người 2 trong đồ án POPS,
gồm 2 trong 3 họ tấn công chính của paper: **Fragmentation (SFrag/BFrag)** và
**Out-of-Bailiwick (SOoB)**. Lab gốc ở thư mục root vẫn được giữ nguyên cho
phần việc của Người 1 (S-type / TXID + source-port guessing).

## Cấu trúc thư mục

| Thư mục | Họ tấn công | Defense | Subnet |
|---------|--------------|---------|--------|
| `oob/`   | SOoB (Out-of-Bailiwick poisoning, multi-vector) | R3 (bailiwick filter) | `10.20.0.0/24` |
| `sfrag/` | SFrag (IPID guessing, second-fragment injection) | R2 (frag-aware truncate) | `10.30.0.0/24` |
| `bfrag/` | BFrag (bullseye IPID, known target) | R2 (frag-aware truncate) | `10.40.0.0/24` |
| `base/`  | Script dùng chung (metrics, pipeline, capture) và unit tests | — | — |

Các lab dùng cùng một cấu trúc 4 service: `client`, `resolver`, `auth`,
`attacker`. Tất cả tham số (TXID space, IPID space, attack rate, defense mode,
poison IP) đều có thể tinh chỉnh qua biến môi trường.

Mặc định các runner dùng **full entropy**: TXID `65536`, source port upstream
random (`UPSTREAM_FIXED_SRC_PORT=0`) và IPID space `65535`, nhưng attacker vẫn
có budget hữu hạn để chạy nhanh trong lab. Nếu cần tái hiện số demo cũ, thêm
suffix `-weak` vào case hoặc đặt `ENTROPY_MODE=weak`. Nếu cần biến thể sát bài
báo hơn, dùng suffix `-bruteforce`/`ENTROPY_MODE=bruteforce` để attacker quét
source-port candidate cùng TXID/IPID.

## Giao diện runner thống nhất

Mỗi lab hỗ trợ 3 case chuẩn:

```bash
docker info
bash ./scripts/run_case.sh baseline   50    # không attack, defense off
bash ./scripts/run_case.sh attack-off 50    # attack đang chạy, defense off
bash ./scripts/run_case.sh attack-on  50    # attack đang chạy, defense on
```

Ví dụ demo yếu entropy:

```bash
bash ./scripts/run_case.sh attack-off-weak 50
```

Ví dụ brute-force đầy đủ hơn cho 150 query:

```bash
bash ./scripts/run_case.sh attack-off-bruteforce 150
```

Sau mỗi run, `scripts/run_case.sh` in:

- `Total / Poisoned / Success rate` đọc từ `/app/result.txt` của client.
- `Latency samples / avg / p95` đọc từ `/app/latency_ms.txt`.

Để lặp nhiều lần lấy mean (recommended cho thống kê có ý nghĩa):

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Pipeline 3-lab cho Người 2

`base/scripts/run_p2_pipeline.sh` chạy toàn bộ 3 lab cho Người 2 và xuất CSV +
bảng tóm tắt Markdown:

```bash
bash labs/base/scripts/run_p2_pipeline.sh --rounds 150 --runs 1 --labs oob,sfrag --entropy full
ENTROPY_MODE=bruteforce bash labs/base/scripts/run_p2_pipeline.sh --rounds 150 --runs 1 --labs oob,sfrag
ENTROPY_MODE=weak bash labs/base/scripts/run_p2_pipeline.sh --rounds 50 --runs 3
python3 labs/base/scripts/analyze_metrics.py ./p2_metrics.csv --md ./p2_summary.md
```

CSV cột: `lab, case, run, rounds, total, poisoned, asr_pct, latency_avg_ms,
latency_p95_ms`.

## Capture pcap để làm bằng chứng

Mỗi lab có thể gọi script chung:

```bash
cd labs/oob
bash ../base/scripts/pcap_capture.sh 10 ./oob.pcap
```

Trong lúc capture đang chạy, mở 1 terminal khác chạy `attack-off`/`attack-on`
case để có gói thật.

## Unit tests (không cần Docker)

```bash
cd labs/base/tests
python3 -m unittest test_oob_resolver_logic.py test_frag_resolver_logic.py -v
```

Test cover:

- Bailiwick logic: `zone_from_qname`, `is_within_bailiwick` (5 test).
- Fragmentation logic: `parse_ipid`, `is_frag1/2_marker`, `Frag2Store`
  put/get/expiry, `handle_frag2_packet` (5 test).

## Ghi chú

- Mỗi lab có subnet riêng để tránh chồng lấn docker network.
- Nếu Docker daemon đang tắt, `run_case.sh` sẽ thoát sớm với thông báo lỗi
  preflight.
- Resolver được khởi tạo với defense ở chế độ `DEFENSE_MODE` (env), nhưng có
  thể đổi runtime qua `toggle_defense.sh on|off` mà không cần restart container.
