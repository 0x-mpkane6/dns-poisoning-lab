# Lab SFrag (IPID guessing fragmentation / R2)

Lab này tái hiện **SFrag** — họ tấn công fragmentation trong paper POPS, trong
đó attacker không biết chính xác IPID của response từ authoritative server và
phải đoán bằng cách flood nhiều `IPID candidate`. Defense là **R2** —
fragmentation-aware response handling.

## Mô hình giả lập fragment

DNS thực dùng IP fragmentation tầng dưới: response > MTU sẽ bị chia thành
fragment 1 (chứa IP/UDP header + DNS header + một phần answer) và fragment 2
(chỉ có IP header tiếp nối với phần payload còn lại). Attacker có thể chèn một
fragment 2 giả mạo nếu đoán đúng IPID, vì IP layer assemble dựa trên IPID và
offset, không có integrity check ở mức UDP/DNS payload.

Để chạy được nhanh trong lab nhỏ (single-MTU UDP), chúng tôi mô phỏng cơ chế
fragmentation ở tầng ứng dụng:

- **Auth server** đính kèm `_fragmeta.example.net IN TXT "TYPE=FRAG1;IPID=<n>"`
  vào additional section của response cho mọi qname có prefix `frag*` —
  đại diện cho fragment 1 mà đã có IP header với IPID = n.
- **Resolver** khi nhận response sẽ:
  - Nếu là FRAG2 marker (`_frag2.example.net.` hoặc TXT chứa `TYPE=FRAG2`):
    lưu vào `Frag2Store` keyed bằng IPID.
  - Nếu là FRAG1 marker: tra `Frag2Store` với cùng IPID; nếu khớp → coi như
    fragment 2 hợp lệ và merge payload (cache record chứa trong frag2 đó).
- **Attacker** flood `IPID_SPACE` packet, mỗi packet mang một (TXT FRAG2 marker,
  A record giả mạo `bank.com -> 6.6.6.6`).

## Chạy nhanh

```bash
docker info
bash ./scripts/run_case.sh baseline   50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on  50
```

Mặc định runner dùng full entropy: TXID 16-bit, source port upstream random,
IPID space `65535`. Muốn chạy lại demo yếu entropy cũ để so sánh:

```bash
bash ./scripts/run_case.sh attack-off-weak 50
bash ./scripts/run_case.sh attack-on-weak  50
```

Chạy biến thể brute-force sát bài báo hơn cho 150 query:

```bash
bash ./scripts/run_case.sh attack-off-bruteforce 150
bash ./scripts/run_case.sh attack-on-bruteforce  150
```

Benchmark:

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Cơ chế phòng thủ R2

`resolver/resolver.py` khi `DEFENSE_MODE=on`: nếu phát hiện FRAG1 marker trong
response upstream → trả `TC=1` cho client, **không** merge bất kỳ frag2 nào đã
được cache. Tương đương với "khi resolver thấy response có khả năng bị
fragmented thì retry qua TCP" — paper R2.

Khi `DEFENSE_MODE=off`, resolver đối chiếu IPID FRAG1 với `Frag2Store` và
greedily merge — đây là hành vi dễ bị poisoning.

## Profile baseline vs attack

- Profile `baseline` ở client → query có prefix `base*` → auth không đính kèm
  FRAG1 marker → resolver chạy đường thường, không ai inject frag2 nên ASR = 0.
- Profile `attack` ở client → query có prefix `frag*` → auth đính kèm FRAG1 →
  attacker inject frag2 → khi defense off và IPID khớp, poisoning xảy ra.

## Biến môi trường chính

| Biến | Mặc định | Vai trò |
|------|----------|---------|
| `ENTROPY_MODE` | `full` | `full` dùng entropy rộng nhưng attacker budget hữu hạn; `weak` dùng demo; `bruteforce` quét source-port × IPID |
| `DEFENSE_MODE` | `off` | bật/tắt R2 |
| `TXID_SPACE` | `65536` | không gian TXID |
| `UPSTREAM_FIXED_SRC_PORT` | `0` | `0` = OS chọn port random; `33333` = demo yếu entropy |
| `IPID_SPACE` | `65535` | không gian IPID đoán |
| `IPID_SCAN_LIMIT` | `8192` | số IPID attacker thử mỗi vòng trong `full`; mode `bruteforce` mặc định `65535` |
| `SRC_PORT_START` | unset | bắt đầu range source-port cần brute-force; mode `bruteforce` mặc định `1024` |
| `SRC_PORT_END` | unset | kết thúc range source-port cần brute-force; mode `bruteforce` mặc định `65535` |
| `SRC_PORT_SCAN_LIMIT` | unset | số port candidate thử trong range; mode `bruteforce` mặc định toàn range |
| `PACKET_CHUNK_SIZE` | `512` | số packet scapy build/send mỗi chunk để tránh giữ toàn bộ brute-force space trong RAM |
| `ATTACK_RATE` | `0.02` | giây nghỉ giữa các vòng flood |
| `POISON_IP` | `6.6.6.6` | IP attacker chèn cho `bank.com` |
| `AUTH_DELAY` | `0.25` | giây delay của authoritative |
| `FRAG_TRIGGER_PREFIX` | `frag` | prefix qname để auth đính FRAG1 marker |

## Xử lý sự cố

- ASR `attack-off` thấp trong full entropy là kỳ vọng. Nếu cần demo tấn công
  thắng race để trình bày R2, chạy `attack-off-weak` hoặc đặt
  `ENTROPY_MODE=weak`.
- Reset: `bash ./scripts/reset.sh`.
