# E3-Extend — Kết quả độ nhạy lưới mở rộng (post-hoc)

## Trạng thái và phạm vi

`E3-Extend` là phân tích **post-hoc, descriptive-only** được thực hiện sau khi E3 đã khóa candidate `8/6.0/0.90` và đã đánh giá held-out đúng một lần. Nó không thay thế E3, không thay candidate đã lock và không tạo một held-out evaluation mới.

Script chỉ mở E3 `validation.csv.gz` đã pin hash: 27.600 decision, 64 paired trace. [`e3_extend_validation.json`](e3_extend_validation.json) xác nhận `PASS` 8/8: 16 candidate đầy đủ, metrics primary/secondary recompute chính xác, CSV khớp JSON, không selection/lock, và ASR vẫn không được đo.

## Lưới khảo sát

Rule được score là:

$$
\mathrm{block}=[samples\ge N]\land[entropy\ge H]\land[unique\_ratio\ge U].
$$

Với $N\in\{8,16,24,48\}$, $H\in\{7,8\}$ và $U\in\{0.95,0.99\}$, có 16 candidate. Metric được report là macro đồng trọng số trên 2 primary attack conditions × 4 levels:

$$
J=\mathrm{attack\text{-}alert}-\mathrm{benign\text{-}trigger},\qquad
\Delta J=J_{\mathrm{new\ B5}}-J_{\mathrm{B2}}.
$$

## Kết quả primary macro

Các giá trị hoàn toàn trùng nhau theo cả bốn $N$ trong lưới này; vì vậy bảng dưới chỉ có bốn operating point khác biệt về outcome.

| H | U | Attack-alert | Benign-trigger | FNR | J = ΔJ vs B2 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 7 | 0.95 | 0.3064 | 0.1799 | 0.6936 | 0.1265 |
| 7 | 0.99 | 0.1829 | 0.0051 | 0.8171 | **0.1778** |
| 8 | 0.95 | 0.0250 | 0.0017 | 0.9750 | 0.0233 |
| 8 | 0.99 | 0.0083 | 0.0000 | 0.9917 | 0.0083 |

Toàn bộ 16 dòng, 8 primary cell/candidate, negative control và failure probes nằm trong [`e3_extend_sensitivity_grid.json`](e3_extend_sensitivity_grid.json) và bản phẳng [`e3_extend_sensitivity_grid.csv`](e3_extend_sensitivity_grid.csv).

## Diễn giải đúng

`H=7,U=0.99` có $\Delta J$ validation lớn nhất trong **lưới post-hoc này**, nhưng attack-alert chỉ 18,29% và FNR 81,71%. Điều đó cho thấy $\Delta J$ đơn lẻ có thể ưu tiên rule rất bảo thủ: benign trigger gần bằng 0 đồng thời phần lớn synthetic attack không bị alert.

Do đó kết quả này là sensitivity finding, không phải bằng chứng candidate đó tốt hơn candidate E3 đã lock và không phải lý do để sửa lock hoặc chạy test lần hai. Không có ASR, poisoning success, resolver outcome, latency, throughput hay resource metric nào được đo từ dataset này.
