# Lab BFrag (Bullseye fragmentation / R2)

BFrag là biến thể "đã biết IPID" của họ Fragmentation trong paper POPS. Khác
với SFrag (đoán IPID, flood một dải lớn), BFrag giả định attacker đã biết
chính xác IPID của response sắp đến từ authoritative — gọi là *bullseye*.

Trong thực tế attacker có thể đạt trạng thái bullseye qua:

- side-channel IPID (Linux: per-flow predictable IPID, Windows: global counter,
  paper Knockel et al. CRYPTREC 2020 phân tích chi tiết),
- hoặc đo IPID đồng hành rồi suy ra.

Trong lab, ta cấu hình thẳng `BULLSEYE_IPID` cho cả auth (đính kèm FRAG1 marker
với IPID này) và attacker (luôn gửi FRAG2 với cùng IPID), nên xác suất race
khi defense off thường rất cao.

## Chạy nhanh

```bash
docker info
bash ./scripts/run_case.sh baseline   50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on  50
```

Mặc định runner dùng full entropy: TXID 16-bit và source port upstream random.
Muốn chạy lại demo yếu entropy cũ:

```bash
bash ./scripts/run_case.sh attack-off-weak 50
bash ./scripts/run_case.sh attack-on-weak  50
```

Benchmark 3 lần:

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Cơ chế phòng thủ R2

Cùng logic như lab SFrag: khi `DEFENSE_MODE=on` và resolver phát hiện FRAG1
marker → trả `TC=1`, không merge frag2. Khi `DEFENSE_MODE=off`, resolver merge
frag2 ngay nếu IPID khớp — vì bullseye, gần như mọi vòng đều bị poisoning.

So sánh trực tiếp giữa SFrag và BFrag là một trong những đo đạc thú vị nhất
của Người 2: BFrag thường có ASR_off ≈ 100% còn SFrag dao động theo
`IPID_SPACE`. Số liệu thực tế trong báo cáo.

## Biến môi trường chính

| Biến | Mặc định | Vai trò |
|------|----------|---------|
| `ENTROPY_MODE` | `full` | `full` dùng entropy rộng; `weak` dùng cấu hình demo |
| `DEFENSE_MODE` | `off` | bật/tắt R2 |
| `TXID_SPACE` | `65536` | không gian TXID |
| `UPSTREAM_FIXED_SRC_PORT` | `0` | `0` = OS chọn port random; `33333` = demo yếu entropy |
| `IPID_SPACE` | `65535` | không gian IPID của auth |
| `BULLSEYE_IPID` | `777` | IPID cố định cho auth + attacker |
| `ATTACK_RATE` | `0.02` | giây nghỉ giữa các vòng flood |
| `POISON_IP` | `6.6.6.6` | IP attacker chèn cho `bank.com` |
| `AUTH_DELAY` | `0.25` | giây delay của authoritative |

## Xử lý sự cố

- Nếu ASR `attack-on` không về 0: kiểm tra log resolver có in `R2 block`,
  và `docker exec resolver cat /app/defense_mode` phải bằng `on`.
- Reset: `bash ./scripts/reset.sh`.
