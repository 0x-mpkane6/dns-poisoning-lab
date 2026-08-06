# E1 — Biên bản kiểm định số liệu (verification memo)

> **CẢNH BÁO — tài liệu này đã LỖI THỜI một phần (2026-08-06).** Biên bản được viết cho phiên bản harness
> trước khi bổ sung biến thể `legacy` (Rℓ2 gốc) và phần mở rộng tải cao (§3.6 của E1_report). Các kiểm tra
> tính đúng đắn/tái lập trong đây vẫn còn hiệu lực (đã chạy lại: `e1_verify.py` 11/11 PASS), nhưng
> run_id/commit và danh sách biến thể trong đây không còn khớp. Số liệu hiện hành: xem `e1_results.json`.

**Mục đích:** xác nhận số liệu E1 đáng tin và đúng yêu cầu outline của thầy, bằng kiểm tra tự tay chạy (không chỉ dựa vào audit trước).
**Ngày:** 2026-08-05 · **Run kiểm định:** `e1_verify.py` (11/11 PASS) + re-run tất định + soát dữ liệu thô.
**Kết luận:** Số liệu E1 **tin cậy**. Tái lập bit-for-bit, primitive detector khớp công thức chuẩn, FPR tái dựng độc lập nhất quán, và bộ yêu cầu E1/P0 của thầy được đáp ứng (trừ metric hệ thống được hoãn có công bố).

---

## 1. Kiểm tra đã chạy và kết quả

| # | Kiểm tra | Cách làm | Kết quả |
|---|---|---|---|
| A | **Tất định / tái lập** | Chạy lại `e1_experiment.py` ra thư mục khác, `diff` với `e1_levels.csv` đã lưu | **IDENTICAL** (bit-for-bit, do seed cố định) |
| B | **Toàn vẹn dữ liệu** | Soát 480 dòng `e1_runs.csv` | 0 run bị cắt (mọi run đủ 300 decision); 0 dòng `blocks > decisions`; 480/480 seed duy nhất |
| C | **entropy đúng công thức** | So `shannon_entropy` (dùng thật trong detector) với `scipy.stats.entropy(base=2)` trên 2000 ca ngẫu nhiên | PASS — sai số tối đa `8.5e-14` |
| D | **luật chặn đúng** | So `r2_should_block('combined')` với cổng AND tường minh `(samples≥24 ∧ entropy≥4.0 ∧ unique≥0.70)` trên lưới s×e×u | PASS toàn bộ lưới; và trả `False` khi `defense_on=False` |
| E | **FPR tái dựng độc lập** | Viết lại mô phỏng FPR **từ đầu** (RNG, cửa sổ, entropy riêng — không dùng vòng lặp của harness), so với `e1_results.json` | PASS — CI độc lập chồng lấn CI đã báo ở mọi mức {12,18,24,36} |
| F | **Clopper–Pearson đúng** | So CI beta-ppf với `scipy.stats.binomtest(...).proportion_ci('exact')` | PASS khớp tuyệt đối; và `0/6000 → [0, 0.00061]` (không báo "FPR = 0") |
| G | **Neo cơ chế (analytic anchors)** | Tải rất thấp (mức 5) và tải rất cao all-distinct (mức 300) | PASS — mức 5 → FPR = 0 (cổng volume đóng); mức 300 → FPR = 1 (ba cổng mở) |

Chạy lại kiểm định: `python e1_verify.py` (thoát 0 nếu toàn bộ PASS).

**Điểm cần lưu ý trung thực (không phải lỗi):** mức **24** là điểm **nhạy seed nhất** vì nằm đúng trên ngưỡng `MIN_SAMPLES`. Mô phỏng độc lập cho CI `[0.549, 0.611]`, báo cáo cho `[0.558, 0.682]` — **hai CI chồng lấn nên nhất quán**, nhưng point-estimate ở 24 dao động ±vài % giữa các bộ seed. Đây chính là lý do E1 báo cáo **khoảng tin cậy** và coi failure boundary là một **vùng (18–36)**, không phải một con số duy nhất. Audit độc lập trước đó (200 run seed mới) cho 0.6179, sát 0.620.

---

## 2. Đối chiếu với yêu cầu E1 của thầy (outline)

| Yêu cầu trong outline | Trạng thái | Bằng chứng |
|---|---|---|
| Mục tiêu: xác định operating boundary + đo FPR ngoài vùng `samples < MIN_SAMPLES` | **Đạt** | Vùng an toàn ≤ ~12; biên ~18–24; bão hoà ~1.0 ở ≥60 (Bảng 1, Hình 1) |
| Biến chính: samples/window ∈ {5,12,18,24,36,60,120,300} | **Đạt** | Đúng 8 mức trong `meta.levels_samples_per_window` |
| Ghi *actual* samples/window (không chỉ mục tiêu) | **Đạt** | Cột `occupancy thực` = `samples_mean` (Bảng 1, Ghi chú 1). query/s = fragment/s = arrival λ = level/2s (benign-on mỗi query đúng 1 FRAG2) |
| ≥ 3 kiểu IPID/source behavior | **Đạt** | `random2048` (đúng auth), `sequential`, `smallpool16` |
| Không bật attacker; window cố định; đổi rate | **Đạt** | Benign-only; window 2.0s cố định; rate đổi qua inter-arrival Poisson (λ) |
| K = 20 independent runs/mức; randomize thứ tự | **Đạt** | K=20; thứ tự cell shuffle bằng `experiment_seed=20260805`; seed mỗi cell độc lập với thứ tự chạy |
| Thu thập entropy, samples, unique_ratio, decision/block count, FPR | **Đạt** | Đủ trong `e1_runs.csv` (kèm tử số blocks / mẫu số decisions từng run) |
| Thu thập latency, throughput, resource overhead | **Hoãn (có công bố)** | Cần testbed Docker; không bịa trong mô phỏng — nêu rõ ở §2.5 + Threats to Validity |
| Đầu ra FPR(rate) và entropy(rate) với 95% CI | **Đạt** | `Figure_1.png` (FPR+CI), `Figure_2.png` (entropy/unique+CI) |
| Bảng failure boundary | **Đạt** | Bảng 1 + phần 4 (biên theo từng behavior) |
| Không gọi FPR = 0 nếu CI còn rộng | **Đạt** | Clopper–Pearson: `0/6000 → [0, 0.00061]` |
| P0 logging: denominator, run ID, seed, config, timestamps | **Đạt** | `e1_results.json.meta` (run_id, generated_utc, commit, config, seed); `e1_runs.csv` (blocks/decisions/seed từng run) |
| E4: đơn vị độc lập = run; CI exact-binomial cho FPR=0; không resample cửa sổ phụ thuộc như độc lập | **Đạt** | Run là đơn vị; t-interval run-level + **cluster bootstrap theo run** + Clopper–Pearson |

**Khoảng trống duy nhất:** metric hệ thống (latency/throughput/CPU/memory) — được **hoãn** sang lần chạy Docker/E5 và **công bố rõ**, không phải bỏ sót. Đây là lựa chọn trung thực vì mô phỏng không đo được chi phí vật lý; bịa số sẽ vi phạm chính quy tắc của thầy.

---

## 3. Vì sao tin được số liệu (tóm tắt)

1. **Tái lập:** cùng seed → cùng byte; đổi seed (200 run trong audit; 60 run ở đây) → cùng kết luận trong CI.
2. **Fidelity:** dùng đúng hàm chấm điểm của `resolver.py`, đã kiểm khớp công thức entropy chuẩn và bảng chân trị luật chặn.
3. **Độc lập:** một bản mô phỏng viết lại từ đầu cho ra cùng đường FPR(level) → không phải lỗi trong một implementation đơn lẻ.
4. **Thống kê đúng chuẩn thầy:** đơn vị run, exact-binomial cho FPR=0, cluster bootstrap cho phụ thuộc trong run.

Tệp liên quan: [`e1_verify.py`](e1_verify.py) (kiểm định), [`E1_report.md`](E1_report.md) (báo cáo), [`e1_results.json`](e1_results.json) / [`e1_runs.csv`](e1_runs.csv) (số liệu thô).
