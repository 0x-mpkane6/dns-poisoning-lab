# Tổng hợp kết quả thực nghiệm

Mỗi kịch bản gồm `150` mẫu. Ba metric được trình bày là Attack Success Rate (ASR), latency trung bình và latency p95. Số liệu SFrag, BFrag và OoB sử dụng profile `weak`; các số liệu còn lại lấy trực tiếp từ artifact của từng biến thể S-type.

## Baseline

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 299.205 | 291.824 |
| Source-port brute-force | 0.00% | 320.214 | 294.206 |
| Kaminsky-style | 0.00% | 298.750 | 291.998 |
| SFrag (`weak`) | 0.00% | 271.194 | 271.535 |
| BFrag (`weak`) | 0.00% | 281.764 | 277.001 |
| Out-of-Bailiwick (`weak`) | 0.00% | 274.846 | 274.278 |

## Attack-off

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force\* | 0.00% | 21.363 | 37.787 |
| Source-port brute-force\* | 0.00% | 18.118 | 28.921 |
| Kaminsky-style\* | 23.33% | 20.117 | 31.485 |
| SFrag (`weak`)\*\* | 98.00% | 271.229 | 272.730 |
| BFrag (`weak`)\*\* | 100.00% | 280.248 | 273.955 |
| Out-of-Bailiwick (`weak`)\*\* | 98.67% | 260.647 | 376.623 |

\* **Cảnh báo phương pháp luận, quan trọng hơn phần lệch 1 dòng dữ liệu ở
dưới:** cả 3 tấn công S-type (TXID/port/Kaminsky, lab `labs/stype`) đo một
cuộc **đua thời gian mức mili-giây** giữa gói giả mạo của attacker và response
thật từ auth (`AUTH_DELAY_SECONDS=0.25`) — không phải một bài toán đoán trong
không gian lớn: `TXID_SPACE=200` và attacker gửi **toàn bộ** 200 giá trị mỗi
vòng (`RESPONSE_BUDGET=200` ≥ `TXID_SPACE`), tức "đoán" luôn trúng, chỉ còn hỏi
gói giả có tới trước response thật hay không. Vì vậy ASR phụ thuộc gần như
hoàn toàn vào lịch trình CPU/ngăn xếp mạng của máy chạy Docker, không phải vào
độ khó thuật toán. Xác minh lại trong phiên này (Docker Compose chính thức,
N=150, code không đổi so với bản tạo ra số gốc) trên máy hiện tại cho:

| Kiểu tấn công | ASR gốc (báo cáo) | ASR chạy lại (phiên xác minh) | Latency trigger gốc | Latency trigger chạy lại |
| --- | ---: | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 40.67% | 21.363 ms | 233.429 ms |
| Source-port brute-force | 0.00% | 44.00% | 18.118 ms | 227.809 ms |
| Kaminsky-style | 23.33% | 31.33% (lần khác: 23.49%\*\*\*, 25.33%, 38.00%) | 20.117 ms | 235.654 ms |

Latency ~20 ms ở cột "gốc" thấp bất thường so với mọi case khác trong cả file
này (baseline/r2entropy/SFrag/BFrag/OoB đều ~260-320 ms, đúng bằng
`AUTH_DELAY_SECONDS`) — dấu hiệu cho thấy trong lần đo gốc, phần lớn 150 vòng
đang lấy lại từ cache thay vì đua lại từ đầu mỗi vòng như thiết kế
(`client/test.sh` gọi truy vấn `_flush.stype-control` để xoá cache mỗi vòng
trước khi đo). Ở máy chạy phiên xác minh này, latency trigger ~230-235 ms
(gần đúng `AUTH_DELAY_SECONDS`) cho thấy mỗi vòng THẬT SỰ đua lại từ đầu, và
ASR 31-44% phản ánh đúng bản chất một cuộc đua gói tin có độ trễ dao động.
**Kết luận: số ASR 0.00%/0.00%/23.33% trong bảng không sai do bịa số, nhưng
không phải một chỉ số ổn định/tái lập được giữa các máy — nó đo hạ tầng chạy
thử nhiều hơn là đo sức mạnh phòng thủ.** Nên đọc 3 dòng TXID/port/Kaminsky ở
trên như "biên độ 0-44% quan sát được", không phải "0.00% là giá trị đúng".
\*\*\* 23.49% = tính lại trên `artifacts/kaminsky/attack-off/result.txt` hiện
có (149/150 dòng, thiếu 1 dòng so với `metrics.txt` ghi `Total: 150`).

\*\* SFrag/BFrag/OoB không mắc vấn đề trên — cơ chế của chúng dựa vào khối
lượng gói gửi trong cả cửa sổ quan sát (không phải thắng một cuộc đua đơn lẻ),
nên ít nhạy với lịch trình CPU hơn nhiều. Xác minh lại N=150 trong phiên này
cho 97.33% / 100.00% / 92.00% — khớp sát với 98.00% / 100.00% / 98.67% gốc
(chênh lệch nằm trong biên độ vài mẫu trên 150, không phải bất thường). Xem
`labs/sfrag/artifacts/verify_weak/`, `labs/bfrag/artifacts/verify_weak/`,
`labs/oob/artifacts/verify_weak/`.

## Attack-on

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 21.958 | 36.979 |
| Source-port brute-force | 0.00% | 16.803 | 29.399 |
| Kaminsky-style | 0.00% | 20.828 | 32.293 |
| SFrag (`weak`) | 0.00% | 275.347 | 274.763 |
| BFrag (`weak`) | 0.00% | 283.898 | 275.370 |
| Out-of-Bailiwick (`weak`) | 0.00% | 254.951 | 382.839 |

Kết luận ASR=0.00% ở cả 3 dòng S-type (defense chặn được) được xác nhận lại
đúng trong phiên xác minh (vẫn 0.00%/0.00%/0.00%) — chỉ latency trigger đo
được cao hơn nhiều (~270-290 ms so với ~17-21 ms gốc), cùng lý do cache đã nêu
ở bảng Attack-off phía trên. Kết luận định tính (defense chặn hoàn toàn) không
đổi.

## Rl2 cải tiến dựa trên entropy

Lab `r2entropy` không có case `benign-off`; ba case thực tế là `baseline`, `benign-on` và `attack-on`. Entropy trung bình được tính từ trường `entropy` trong `r2_entropy_decisions.jsonl`.

| Case | ASR | Entropy IPID trung bình | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 0.00% | N/A | 314.476 | 288.744 |
| Benign-on | 0.00% | 0.000 | 275.479 | 287.106 |
| Attack-on | 0.00% | 10.836 | 304.422 | 279.118 |

Baseline không chứa frag1/frag2 nên resolver không tạo entropy decision. Trong `benign-on`, cả `150/150` decision đều là `allow`. Trong `attack-on`, entropy trung bình `10.836` vượt ngưỡng cấu hình `4.0` và cả `148/148` decision được ghi nhận là `tc_block`. Kết quả cho thấy rule không chặn luồng fragment hợp lệ nhưng phát hiện được SFrag flood có phân bố IPID hỗn loạn.

### Cập nhật: benign-on với lưu lượng fragment hợp lệ thật (không còn entropy=0 mặc định)

Bảng `benign-on` phía trên có `entropy = 0.000` vì lý do máy móc: `total_frag2_observed = 0` trong suốt case đó (xem `artifacts/r2entropy/benign-on/r2_entropy_summary.json`) — chưa từng có gói frag2 (offset>0) hợp lệ nào thực sự đến resolver, nên `shannon_entropy([])` luôn trả 0 trên một cửa sổ rỗng. Nói cách khác, "150/150 allow" đúng nhưng chưa từng được kiểm chứng bằng lưu lượng fragment hợp lệ thật.

`labs/r2entropy/auth/auth_server.py` được sửa để auth tự phát thêm một gói FRAG2 hợp lệ (cùng IPID với FRAG1, không Answer/poison) ngay sau mỗi response bị đánh dấu fragment trong case `benign-on` — đúng bản chất vật lý của IP fragmentation (các fragment của cùng một datagram luôn chung IPID). `baseline`/`attack-on` không đổi.

| Case | Nguồn | N | ASR | Avg Lat (ms) | p95 (ms) | Decision | Entropy avg | Samples avg (min/max) |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | --- |
| Benign-on (cũ, trước fix) | `artifacts/r2entropy/benign-on/` | 150 | 0.00% | 275.479 | 287.106 | 150 allow / 0 block | 0.000 (samples luôn 0) | 0 |
| Benign-on (đã fix) | `artifacts/r2entropy/benign-on-fixed/benign-on/` | 150 | 0.00% | 299.204 | 275.310 | 150 allow / 0 block | 2.4045 | 5.573 (0/6) |

Số liệu "đã fix" đo bằng đúng **Docker Compose chính thức** (`scripts/run_case.sh`,
4 container thật, `dnslib` thật, mạng bridge `10.60.0.0/24` thật, N=150 đầy đủ) —
không còn qua bước trung gian nào. (Lần đo đầu tiên của kết quả này thực ra
dùng một harness chạy ngoài Docker vì môi trường đo lúc đó không có Docker
Desktop; sau khi xác nhận Docker chạy được, đã đo lại bằng đúng topology
Docker chính thức và **thay thế** số liệu harness đó — số trong bảng trên là
số Docker, không phải số harness.)

Kết luận không đổi (allow 100%, FPR=0% ở tốc độ lưu lượng hợp lệ này), nhưng giờ đây kết luận đó dựa trên entropy đo được thật (~2.4 bit từ trung bình ~5.6 mẫu IPID hợp lệ/cửa sổ 2 giây) thay vì một giá trị mặc định của cửa sổ rỗng.

### Các bug đã sửa để chạy được Docker Compose chính thức

Trước khi đo được số liệu "đã fix" ở trên bằng Docker thật, phải sửa 2 bug có sẵn trong `scripts/run_case.sh` (cả
`r2entropy` và `stype`), lộ ra lần đầu tiên khi thực sự thử chạy bằng Docker
thật trên Windows:

1. `snapshot_case_artifacts()`/`toggle_benign_frag2()` gọi lệnh `compose ...`
   trần (không phải `docker compose ...`) — không nơi nào trong repo định
   nghĩa alias `compose`, nên script luôn `command not found` và dừng ngay
   (`set -euo pipefail`) trừ khi shell của người chạy tự có alias đó từ
   trước. Đây rất có thể là lý do các lần chạy Docker trước đây không thành
   công. Đã sửa toàn bộ các chỗ gọi `compose` trần trong 5 file
   (`labs/r2entropy/scripts/run_case.sh`, `run_all_cases.sh`, `reset.sh`,
   `labs/stype/scripts/run_case.sh`, `run_all_cases.sh`) thành
   `docker compose ...`.
2. `snapshot_case_artifacts()` dùng `docker cp <container>:<path> <out_dir>`
   để lưu `result.txt`/`latency_ms.txt`/`r2_entropy_decisions.jsonl`... —
   trên Docker Desktop for Windows, `docker cp` diễn giải sai đường dẫn đích
   kiểu MSYS (`/d/...` bị biến thành `D:\d\...`) và lỗi thầm lặng (bị nuốt
   bởi `|| true`), y hệt vấn đề mà `measure_asr.sh`/`measure_latency.sh` đã
   né bằng cách stream qua `docker compose exec ... cat` thay vì `docker cp`.
   Đã đổi `snapshot_case_artifacts()` trong cả hai lab sang cùng cách stream
   này.

Số benign-on Docker N=150 đã hiển thị ở bảng phía trên
(`artifacts/r2entropy/benign-on-fixed/benign-on/`). Case `attack-on` (đối
chứng, code không đổi) cũng được đo lại cùng đợt để kiểm tra không có gì hỏng:

| Case | Nguồn | N | ASR | Avg Lat (ms) | p95 (ms) | Decision | Entropy avg | Samples avg (min/max) | Unique ratio avg |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | --- | ---: |
| Attack-on (Docker thật, xác minh lại) | `artifacts/r2entropy/benign-on-fixed/attack-on/` | 150 | 0.00% | 296.631 | 279.118 | 147 block / 1 allow | 10.1704 | 1250.4 | ~1.0 |

`total_frag2_observed=149/150` cho benign-on — khớp với cơ chế mô tả ở trên.
147/148 (không phải 148/148, số gốc trong bảng đầu file) cho attack-on chỉ
khác nhau ở quyết định đầu tiên của cửa sổ (trước khi đủ mẫu để vượt
`R2_MIN_SAMPLES=24`), không đổi kết luận (entropy ~10 bit, vẫn `tc_block`).

## Nguồn dữ liệu

- `artifacts/txid/`
- `artifacts/port/`
- `artifacts/kaminsky/`
- `artifacts/sfrag-weak/`
- `artifacts/bfrag-weak/`
- `artifacts/oob-weak/`
- `artifacts/r2entropy/baseline/`, `artifacts/r2entropy/benign-on/`, `artifacts/r2entropy/attack-on/` (số liệu gốc, trước fix)
- `artifacts/r2entropy/benign-on-fixed/{baseline,benign-on,attack-on}/` (Docker Compose chính thức, N=150 — bộ số liệu "đã fix" duy nhất, đã hợp nhất; xem mục "Rl2 cải tiến dựa trên entropy" ở trên)
- `labs/stype/artifacts/verify_20260703/{txid,port,kaminsky}/{baseline,attack-off,attack-on}/` (Docker thật, N=150, xác minh lại toàn bộ 3 biến thể S-type — phát hiện vấn đề nhạy cảm thời gian, xem ghi chú ở bảng Attack-off)
- `labs/sfrag/artifacts/verify_weak/`, `labs/bfrag/artifacts/verify_weak/`, `labs/oob/artifacts/verify_weak/` (Docker thật, N=150, xác minh lại SFrag/BFrag/OoB weak)
- `labs/sfrag/artifacts/verify_weak/`, `labs/bfrag/artifacts/verify_weak/`, `labs/oob/artifacts/verify_weak/` (Docker thật, N=150, xác minh lại SFrag/BFrag/OoB weak)
