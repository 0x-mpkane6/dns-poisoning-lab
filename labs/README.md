# Ghi chú thư mục labs

Thư mục `labs/` chứa các môi trường Docker lab dùng để mô phỏng DNS cache poisoning và các rule phòng thủ theo hướng POPS/DNS-CPM.

Mỗi lab chính thường có cùng cấu trúc:

```text
<lab>/
+-- client/      # Gửi DNS query, ghi result.txt và latency_ms.txt
+-- resolver/    # Resolver mô phỏng cache và rule phòng thủ
+-- auth/        # Authoritative DNS server hợp lệ
+-- attacker/    # Script tấn công hoặc spoof packet
+-- scripts/     # Script chạy case, reset, đo metrics
+-- docker-compose.yml
```

## Danh sách thư mục

| Thư mục | Mục đích |
| --- | --- |
| `base/` | Chứa script dùng chung cho các lab: preflight Docker, start stack, toggle defense, đo ASR, đo latency. Đây không phải lab độc lập. |
| `stype/` | Mô phỏng S-type attacks gồm TXID brute-force, source-port brute-force và Kaminsky-style. Defense tương ứng là `Rl1`. |
| `oob/` | Mô phỏng out-of-bailiwick poisoning, attacker chèn record `bank.com -> 6.6.6.6` vào additional section. Defense tương ứng là `Rl3`. |
| `sfrag/` | Mô phỏng SFrag, attacker đoán IPID và chèn frag2 giả. Defense tương ứng là `Rl2` cơ bản. |
| `bfrag/` | Mô phỏng BFrag, attacker dùng IPID mục tiêu cố định để chèn frag2 giả. Defense tương ứng là `Rl2` cơ bản. |
| `r2entropy/` | Mô phỏng cải tiến `Rl2`: ghi nhận frag2 có offset > 0, tính entropy IPID và chỉ block khi thấy dấu hiệu flood bất thường. |

## Topology chung

Mỗi lab chạy trong Docker bridge network riêng, nhưng đều gồm 4 thành phần:

```text
client  --->  resolver  --->  auth
                ^
                |
             attacker
```

Vai trò:

| Thành phần | Vai trò |
| --- | --- |
| `client` | Gửi query đến resolver và ghi kết quả đo. |
| `resolver` | Xử lý query, cache bản ghi DNS và áp dụng rule phòng thủ. |
| `auth` | Trả lời DNS hợp lệ với độ trễ có chủ đích để tạo cửa sổ race. |
| `attacker` | Gửi response giả mạo hoặc frag2 giả về resolver. |

## Subnet từng lab

| Lab | Subnet | Client | Resolver | Auth | Attacker |
| --- | --- | --- | --- | --- | --- |
| `oob` | `10.20.0.0/24` | `10.20.0.10` | `10.20.0.53` | `10.20.0.100` | `10.20.0.200` |
| `sfrag` | `10.30.0.0/24` | `10.30.0.10` | `10.30.0.53` | `10.30.0.100` | `10.30.0.200` |
| `bfrag` | `10.40.0.0/24` | `10.40.0.10` | `10.40.0.53` | `10.40.0.100` | `10.40.0.200` |
| `stype` | `10.50.0.0/24` | `10.50.0.10` | `10.50.0.53` | `10.50.0.100` | `10.50.0.200` |
| `r2entropy` | `10.60.0.0/24` | `10.60.0.10` | `10.60.0.53` | `10.60.0.100` | `10.60.0.200` |

## Cách chạy chung

Vào thư mục lab cần chạy:

```bash
cd labs/<ten-lab>
```

Nếu chạy trên WSL/Linux và file vừa được sửa từ Windows:

```bash
dos2unix ../base/scripts/*.sh scripts/*.sh client/test.sh resolver/toggle_defense.sh
```

Build và reset stack:

```bash
docker-compose down -v --remove-orphans
docker-compose build
```

Chạy tất cả case của lab:

```bash
bash ./scripts/run_all_cases.sh
```

Hoặc chạy từng case:

```bash
bash ./scripts/run_case.sh baseline
bash ./scripts/run_case.sh attack-off
bash ./scripts/run_case.sh attack-on
```

Riêng `r2entropy/` không tập trung đo `attack-off`; các case chính là:

```bash
bash ./scripts/run_case.sh baseline
bash ./scripts/run_case.sh benign-on
bash ./scripts/run_case.sh attack-on
```

## Pipeline OOB/SFrag 150 query

Các runner của `oob` và `sfrag` hỗ trợ ba cấu hình entropy:

| Mode | Ý nghĩa |
| --- | --- |
| `weak` | Demo dễ tái hiện: source port cố định, TXID/IPID space nhỏ. |
| `full` | Entropy rộng nhưng attacker chỉ dùng packet budget hữu hạn để chạy nhanh. |
| `bruteforce` / `paper` | Quét source-port candidate cùng toàn bộ TXID/IPID space, sát giả định blind brute-force hơn. |

Chạy lại hai lab chính với 150 query:

```bash
bash labs/base/scripts/run_p2_pipeline.sh --rounds 150 --runs 1 --labs oob,sfrag --entropy weak --no-multi --no-sweep
bash labs/base/scripts/run_p2_pipeline.sh --rounds 150 --runs 1 --labs oob,sfrag --entropy bruteforce --no-multi --no-sweep
```

Kết quả batch mới nằm trong:

```text
Report/data/docker_weak_150/
Report/data/docker_bruteforce_150/
Report/data/p2_150_comparison.md
```

Nếu cần format giống các kết quả của Phúc Khang trong `artifacts/`, chạy thêm
`--artifact-dir artifacts`. Khi đó mỗi case có đủ `metrics.txt`, `result.txt`
và `latency_ms.txt`:

```text
artifacts/oob-weak/<case>/
artifacts/sfrag-weak/<case>/
artifacts/oob-bruteforce/<case>/
artifacts/sfrag-bruteforce/<case>/
```

## Kết quả đầu ra

Kết quả sau khi chạy được lưu trong thư mục `artifacts/` ở root repository.

File thường gặp:

| File | Ý nghĩa |
| --- | --- |
| `metrics.txt` | Tổng số mẫu, số lần bị poison, success rate, latency avg và p95. |
| `result.txt` | Kết quả truy vấn `bank.com` từng round. |
| `latency_ms.txt` | Độ trễ từng round. |
| `resolver.log` | Log xử lý của resolver nếu lab có lưu. |
| `attack.log` | Log của attacker nếu lab có lưu. |

Trong kết quả:

```text
203.0.113.80 = IP hợp lệ của bank.com
6.6.6.6      = IP giả/poison của attacker
```

Riêng `r2entropy/` có thêm:

| File | Ý nghĩa |
| --- | --- |
| `frag2_events.jsonl` | Các frag2 quan sát được: src, dst, src_port, dst_port, ipid, offset. |
| `r2_entropy_decisions.jsonl` | Quyết định allow/block dựa trên entropy IPID. |
| `r2_entropy_summary.json` | Tổng hợp số frag2, số block và decision cuối cùng. |
