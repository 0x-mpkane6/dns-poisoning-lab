# Lab OoB (SOoB / R3)

Lab này tái hiện họ tấn công **SOoB** (Out-of-Bailiwick cache poisoning) trong
paper *POPS: From History to Mitigation of DNS Cache Poisoning Attacks* (Afek
et al., USENIX Security 2025). Defense được mô phỏng là **R3** — bộ lọc
bailiwick.

## Topology

```
client (10.20.0.10) ───► resolver (10.20.0.53) ───► auth (10.20.0.100)
                              ▲
                              │ (DNS spoof, source-IP = auth)
                          attacker (10.20.0.200)
```

- Client dùng `dig` qua resolver để query subdomain ngẫu nhiên trong
  `example.net`, sau đó kiểm tra `bank.com` đã bị poisoning hay chưa.
- Resolver: Python + dnslib, mặc định dùng TXID 16-bit (`65536`) và source port
  upstream random do OS chọn. Muốn tái hiện demo yếu entropy cũ thì chạy
  `ENTROPY_MODE=weak` hoặc dùng suffix `-weak`. Muốn chạy biến thể sát bài báo
  hơn, dùng `ENTROPY_MODE=bruteforce`/suffix `-bruteforce` để attacker quét
  cả source-port candidate lẫn TXID. R3 toggle qua `/app/defense_mode`.
- Auth: phục vụ zone `example.net.` với delay `AUTH_DELAY_SECONDS=0.25` giây
  để tạo cửa sổ race cho attacker.
- Attacker: scapy flood gói DNS giả, chèn các record OoB vào additional/authority
  section.

## Vector tấn công OoB

Script `attacker/scripts/spoof.py` hỗ trợ 2 profile qua biến `ATTACK_PROFILE`:

| Profile | Vector |
|---------|--------|
| `default` (mặc định) | (1) Inject `bank.com -> 6.6.6.6` ở **Additional** section. |
| `multi`              | (1) + (2) NS hijack `example.net IN NS ns1.evil.com` ở **Authority** + glue `ns1.evil.com -> 7.7.7.7` ở **Additional** + (3) Sibling poison `evilbank.com -> 6.6.6.6` ở **Additional**. |

Profile `multi` minh họa rằng R3 phải lọc *mọi* OoB record trong tất cả các
section, không chỉ riêng record nổi bật.

## Cơ chế phòng thủ R3

`resolver/resolver.py` khi `DEFENSE_MODE=on`:

1. So qname trong response question section với qname gốc resolver gửi đi.
   Nếu khác → `TC=1`, không cache.
2. Duyệt mọi A record (Answer / Authority / Additional). Nếu có record nào
   `rrname` không nằm trong bailiwick zone của qname → log đầy đủ
   `qname / section / out_of_bailiwick → ip` rồi trả `TC=1`.
3. Nếu mọi record hợp lệ → cache.

Khi `DEFENSE_MODE=off`, resolver greedily cache mọi A record (mô phỏng phiên
bản resolver lỏng, kiểu Bind 9.4 trước CVE-2008-1454).

## Chạy nhanh

```bash
docker info
bash ./scripts/run_case.sh baseline   50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on  50
```

Mặc định là full entropy. Chạy demo yếu entropy như số liệu cũ:

```bash
bash ./scripts/run_case.sh attack-off-weak 50
bash ./scripts/run_case.sh attack-on-weak  50
```

Chạy brute-force đầy đủ hơn cho 150 query:

```bash
bash ./scripts/run_case.sh attack-off-bruteforce 150
bash ./scripts/run_case.sh attack-on-bruteforce  150
```

Benchmark 3 lần để giảm dao động:

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

Đổi sang multi-vector:

```bash
ATTACK_PROFILE=multi bash ./scripts/run_case.sh attack-off 50
```

## Capture bằng chứng (pcap)

Trong lúc attacker đang chạy, mở terminal khác:

```bash
bash ../base/scripts/pcap_capture.sh 10 ./oob_off.pcap
```

Gợi ý phân tích trên Wireshark: filter `udp.port == 53`. Bạn sẽ thấy chuỗi
TXID tăng (attacker flood) và `additional records` chứa OoB record `bank.com`.

## Biến môi trường chính

| Biến | Mặc định | Vai trò |
|------|----------|---------|
| `ENTROPY_MODE` | `full` | `full` dùng TXID 16-bit + source port random nhưng attacker budget hữu hạn; `weak` dùng demo; `bruteforce` quét source-port × TXID |
| `DEFENSE_MODE` | `off` | trạng thái khởi tạo của resolver |
| `TXID_SPACE` | `65536` | không gian TXID |
| `TXID_SCAN_LIMIT` | `4096` | số TXID attacker thử mỗi vòng trong `full`; mode `bruteforce` mặc định `65536` |
| `UPSTREAM_FIXED_SRC_PORT` | `0` | `0` = OS chọn port random; `33333` = demo yếu entropy |
| `RESOLVER_UPSTREAM_PORT` | `33333` | port attacker đoán khi không biết source port thật |
| `SRC_PORT_START` | unset | bắt đầu range source-port cần brute-force; mode `bruteforce` mặc định `1024` |
| `SRC_PORT_END` | unset | kết thúc range source-port cần brute-force; mode `bruteforce` mặc định `65535` |
| `SRC_PORT_SCAN_LIMIT` | unset | số port candidate thử trong range; mode `bruteforce` mặc định toàn range |
| `PACKET_CHUNK_SIZE` | `512` | số packet scapy build/send mỗi chunk để tránh giữ toàn bộ brute-force space trong RAM |
| `ATTACK_RATE` | `0.03` | giây nghỉ giữa các vòng flood |
| `POISON_IP` | `6.6.6.6` | IP attacker chèn cho `bank.com` |
| `AUTH_DELAY` | `0.25` | giây delay của authoritative để tạo race |
| `ATTACK_PROFILE` | `default` | `default` hoặc `multi` |

## Xử lý sự cố

- ASR `attack-off` thấp bất thường (<20%): tăng `ROUNDS`, giảm `ATTACK_RATE`,
  kiểm tra `docker compose logs attacker` đảm bảo flood đang chạy trước trigger.
- ASR `attack-on` không về 0: kiểm tra log resolver có in dòng `R3 block` chưa,
  và `docker exec resolver cat /app/defense_mode` phải là `on`.
- Reset toàn lab: `bash ./scripts/reset.sh`.
