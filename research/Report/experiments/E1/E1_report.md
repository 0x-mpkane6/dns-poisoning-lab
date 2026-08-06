# E1

---

## 1. Câu hỏi và mục tiêu

> **RQ1 - FPR của Rℓ₂ thay đổi thế nào khi tốc độ fragment hợp lệ tăng?**
> *Bằng chứng cần có:* đường FPR–rate với 95% CI; xác định miền vận hành an toàn và failure boundary.

E1 chạy detector trên **chỉ lưu lượng fragment HỢP LỆ** (không bật attacker). Vì không có tấn công, **mọi quyết định `tc_block` đều là báo động nhầm** (false positive). Ta quét tải benign (samples/window) và đo:

$$\text{FPR} = \frac{\text{số quyết định benign bị chặn (tc\_block)}}{\text{tổng số decision event}}$$

Mục tiêu: tìm **vùng an toàn** và **điểm detector bắt đầu chặn nhầm người dùng thật** (failure boundary), có khoảng tin cậy.

Đây cũng là lời đáp trực tiếp cho vấn đề mà số liệu benign cũ *không* trả lời được: trước đây `entropy = 0.000, 150 allow` chỉ vì `total_frag2_observed = 0`. Sau Task 1 thì có dữ liệu thật nhưng chỉ ở tải rất thấp (~5,5 mẫu/cửa sổ, trong khi ngưỡng là 24) - detector **chưa bao giờ thực sự phải ra quyết định khó**.
> E1 đẩy tải lên đủ cao để buộc detector phải quyết định.

---

## 2. Phương pháp

### 2.1 Detector dưới thử nghiệm: Rℓ2 gốc vs Rℓ2 cải tiến của nhóm

Detector là luật **Rℓ2** của POPS (Afek et al., USENIX Security 2025). Hai bản:

- **Rℓ2 GỐC (legacy)** — theo paper (Algorithm 3): *hễ thấy fragment là chặn* (mảnh đầu → mitigation TC/TCP; mọi mảnh-thứ-hai → hủy). Không dùng IPID/entropy. Hệ quả: **mọi phản hồi phân mảnh hợp lệ đều bị ép sang TCP** (FPR phát hiện = 100%).
- **Rℓ2 CẢI TIẾN của nhóm (combined = B5)** — thay luật "chặn sạch" bằng thống kê IPID của các FRAG2 trong cửa sổ, **chỉ chặn khi giống một SFrag flood**. Mục tiêu: **giảm false positive** trên fragment hợp lệ (không ép sang TCP một cách không cần thiết).

**Bộ 3 ngưỡng nhóm tối ưu (operating point B5):**

| Tham số | Giá trị |
| --- | --- |
| `R2_MIN_SAMPLES` | 24 |
| `R2_ENTROPY_THRESHOLD` | 4.0 |
| `R2_UNIQUE_RATIO_THRESHOLD` | 0.70 |
| `FRAG2_WINDOW_SECONDS` | 2.0 s |

Luật B5: **chặn ⟺ `samples ≥ 24` VÀ `entropy ≥ 4.0` VÀ `unique_ratio ≥ 0.70`** (cổng AND ba tín hiệu). E1 so trực tiếp FPR của **Rℓ2 gốc** với **Rℓ2 cải tiến** trên fragment hợp lệ, để đo lợi ích giảm FP mà cải tiến mang lại. (B2/B3/B4 là ablation từng tín hiệu.)

### 2.2 Mô hình IPID hợp lệ (đúng `auth_server.py`) và 3 kiểu nguồn

Trong `benign-on`, mỗi truy vấn `frag*` khiến auth phát một FRAG2 hợp lệ mang `IPID = randint(0, IPID_SPACE−1)`. E1 dùng **ba kiểu IPID/source behavior** (outline yêu cầu tối thiểu ba), mô phỏng ba cách một host/middlebox hợp lệ gán trường IP-ID 16-bit:

| Mã | Mô hình | Đại diện thực tế |
| --- | --- | --- |
| `random2048` | IPID ~ Uniform{0..2047} | **Đúng model `auth_server.py`** - stack randomize IPID |
| `sequential` | IPID = bộ đếm toàn cục +1 (mod 2048) | Linux/Windows đời cũ, IPID đơn điệu |
| `smallpool16` | IPID ~ Uniform{0..15} | NAT/middlebox hoặc thiết bị nghèo tài nguyên tái dùng IPID |

### 2.3 Tải, số lần lặp, kiểm soát (theo E1 + protocol E4)

- **Biến chính:** target **samples/window thuộc {5, 12, 18, 24, 36, 60, 120, 300}**. Arrival là quá trình Poisson tốc độ `λ = level / 2.0 s`, nên kỳ vọng số mẫu trong mỗi cửa sổ đúng bằng `level`.
- **Kiểm soát:** không bật attacker; window và mô hình nguồn cố định; warm-up bỏ `3×window` giây đầu (giai đoạn cửa sổ chưa đầy - đúng hiện tượng ramp-up quan sát được ở testbed thật: samples đi 0,1,2,…).
- **Lặp:** **K = 20 independent runs/cell**, mỗi run 300 decision event; **thứ tự thực thi các cell được randomize**; mỗi cell có **seed riêng, ghi log** (độc lập với thứ tự chạy).
- **Đơn vị phân tích:** một **run** là đơn vị độc lập (các cửa sổ chồng lấn trong cùng run **không** độc lập).

### 2.4 Thống kê (theo E4 và quy tắc "FPR = 0")

- **CI chính (run-level):** FPR mỗi run = blocks/decisions; báo trung bình ± **95% t-interval** trên 20 run.
- **Cluster/hierarchical bootstrap:** resample nguyên **run** (5000 lần) -> CI cho FPR gộp.
- **Exact binomial (Clopper–Pearson):** cho mọi mức, đặc biệt khi **FPR = 0** - báo dạng khoảng `[0, upper]`, **không** diễn giải `0/n` là "FPR thật bằng 0". (Ở đây mỗi cell gộp 20×300 = 6000 decision, nên 0 block -> CP 95% = `[0, 0.00061]`.)

### 2.5 Vì sao là mô phỏng, không phải Docker

Docker daemon không chạy; client `dig` không có trên Windows; và quan trọng nhất: `auth_server.py` **tuần tự hoá** mỗi truy vấn bằng `AUTH_DELAY = 0.25 s` -> tối đa ~4 query/s -> ~8 mẫu/cửa sổ, **không thể** đạt các mức {24, 36, 60, 120, 300} mà E1 yêu cầu. Đây đúng là điều README framework đã ghi: *"CPU/memory và throughput cần được bổ sung trước khi chạy ma trận E1–E4 chính."* Do đó E1 chạy trên **testbed mô phỏng đã kiểm chứng** (cùng mã detector). **Kiểm chứng fidelity:** ở tải thấp ~5–6 mẫu/cửa sổ, mô phỏng tái tạo đúng số liệu testbed thật - `entropy = log₂(6) = 2.585`, `unique_ratio ≈ 1.0`, **0 block** (xem `artifacts/r2entropy/benign-on-fixed`).

**Lưu ý - metric hệ thống.** Latency p50/p95/p99, throughput và CPU/memory không được đo trong mô phỏng (cần testbed Docker/E5) và được hoãn sang lần chạy đó; không bịa số. E1 tập trung vào phần cốt lõi của RQ1: đường FPR(rate) và cơ chế entropy/unique_ratio(rate).

---

## 3. Kết quả

### 3.1 Hình 1 - FPR theo tốc độ fragment hợp lệ (Rℓ2 gốc vs Rℓ2 cải tiến)

![Figure 1 - FPR vs benign fragment rate](figures/Figure_1.png)

**Hình 1.** FPR trên lưu lượng fragment hợp lệ theo tải (trục hoành log). Giải thích:

- Thí nghiệm chỉ phát lưu lượng **hợp lệ**, không bật attacker → **mọi lần chặn đều là báo động nhầm** (response bị ép sang TCP).
- **Đường đen đứt (hình thoi)** — Rℓ2 gốc: chặn mọi fragment nên FPR = 1.000 ở mọi mức tải.
- **Ba đường màu** — Rℓ2 cải tiến của nhóm, trên ba kiểu nguồn IPID: FPR ≈ 0 ở tải thấp, tăng nhanh quanh ngưỡng, rồi thoái hoá về ~1.0 ở tải cao.
- **Vùng bóng mờ** quanh mỗi đường: khoảng tin cậy 95% tính theo run (K = 20 run/mức).
- **Đường đứt dọc**: `MIN_SAMPLES = 24`, tức ngưỡng số lượng của luật cải tiến.
- Khoảng cách theo chiều dọc giữa đường đen và các đường màu chính là **lượng false positive mà cải tiến loại bỏ được**.

### 3.2 Bảng 1 - FPR của B5 (combined) theo mức tải

FPR (run-mean) với 95% CI run-level và Clopper–Pearson; entropy và unique_ratio trung bình. Mỗi cell: 20 run × 300 decision = 6000 decision. Cột "occupancy thực" là số mẫu trung bình thực trong cửa sổ (`samples_mean`) - xem Ghi chú 1 về chênh lệch so với mức tải mục tiêu.

**`random2048` - Random IPID (đúng model `auth_server.py`):**

| samples/window (mục tiêu) | occupancy thực | FPR (run-mean) | 95% CI (run-level) | 95% CI (Clopper–Pearson) | entropy | unique_ratio |
| ---: | ---: | ---: | :--: | :--: | ---: | ---: |
| 5 | 5.9 | 0.000 | [0.000, 0.000] | [0.0000, 0.00061] | 2.453 | 0.999 |
| 12 | 12.6 | 0.001 | [0.000, 0.003] | [0.00058, 0.00263] | 3.594 | 0.998 |
| **18** | 19.0 | **0.140** | **[0.098, 0.182]** | [0.1315, 0.1492] | 4.205 | 0.996 |
| **24** | 24.9 | **0.620** | **[0.558, 0.682]** | [0.6078, 0.6325] | 4.596 | 0.994 |
| 36 | 37.1 | 0.985 | [0.972, 0.999] | [0.9820, 0.9882] | 5.173 | 0.991 |
| 60 | 59.2 | 1.000 | [1.000, 1.000] | [0.9994, 1.0000] | 5.845 | 0.985 |
| 120 | 118.1 | 1.000 | [1.000, 1.000] | [0.9994, 1.0000] | 6.827 | 0.975 |
| 300 | 301.7 | 1.000 | [1.000, 1.000] | [0.9994, 1.0000] | 8.088 | 0.928 |

**Ghi chú 1 (occupancy vs mức tải mục tiêu).** "samples/window = N" là mức tải mục tiêu (kỳ vọng số arrival Poisson trong một cửa sổ). Occupancy trung bình thực ≈ N + ~1 vì sự kiện vừa đến được tính trong cửa sổ của chính nó (đúng như luồng `observe()`->`score()` của `resolver.py`). Do đó "FPR ~0.62 tại ngưỡng 24" thực chất ứng với occupancy trung bình ~24.9. Điều này không đổi kết luận (biên vẫn nằm ngay quanh MIN_SAMPLES), chỉ làm rõ trục hoành là tải mục tiêu chứ không phải occupancy chính xác.

**Ghi chú 2 (khoảng tin cậy).** CI run-level (t-interval) là phụ cho các cell gần 0/gần 1: t-interval trên tỉ lệ có thể cho cận ngoài [0,1] (đã kẹp hiển thị về [0,1]); với các cell đó Clopper–Pearson và cluster bootstrap là khoảng chính. Ở vùng chuyển tiếp (18–36) hai cách nhất quán.

**`sequential` - Sequential IPID (+1):** hành vi gần như trùng `random2048` (unique_ratio ≡ 1.0): FPR = 0.000 -> 0.003 -> **0.167** (s=18) -> **0.563** (s=24) -> 0.988 (s=36) -> 1.000 (s≥60). Failure boundary ~18.

**`smallpool16` - Small IPID pool (NAT/constrained):** FPR = **0.000 ở MỌI mức** (CP 95% `[0, 0.00061]`). Nguồn IPID nghèo làm `unique_ratio` tụt dưới 0.70 -> cổng unique **không mở** -> B5 (AND) không bao giờ chặn.

### 3.3 Hình 2 - Cơ chế: entropy & unique_ratio so với hai cổng

![Figure 2 - entropy and unique_ratio vs rate](figures/Figure_2.png)

**Hình 2.** Giá trị hai tín hiệu IPID theo tải, đặt cạnh ngưỡng tương ứng. Giải thích:

- **Panel (a) — entropy.** Với `random IPID`/`sequential IPID`, entropy vượt ngưỡng **4.0** ngay từ samples/window ≈ 16–18 và tiếp tục tăng theo `≈ log₂(samples)`. Với `small IPID pool`, entropy bị chặn trần ở `log₂(16) = 4.0` nên hầu như không vượt ngưỡng.
- **Panel (b) — unique_ratio.** `random`/`sequential` giữ `unique_ratio ≈ 1.0` (IPID gần như không trùng) nên **luôn** vượt ngưỡng 0.70; `small IPID pool` tụt xuống dưới 0.70 từ samples/window ≈ 12 nên **không** vượt.
- Hai panel giải thích Hình 1: nguồn IPID đa dạng làm **cả hai** cổng mở khi tải tăng → luật cải tiến thoái hoá thành chặn theo số lượng; nguồn IPID nghèo bị cổng `unique_ratio` giữ lại → FPR = 0.
- Đường đứt ngang = ngưỡng của tín hiệu; đường chấm dọc = `MIN_SAMPLES = 24`; vùng bóng mờ = 95% CI.

### 3.4 Bảng 2 - Ablation preview (FPR gộp, `random2048`)

So sánh cùng lúc B5 với các cổng đơn - hé lộ tín hiệu nào thực sự điều khiển FPR:

| samples/window | B5 combined | B2 volume-only | B3 entropy-only | B4 unique-only |
| ---: | ---: | ---: | ---: | ---: |
| 5 | 0.000 | 0.000 | 0.000 | 0.999 |
| 12 | 0.001 | 0.001 | 0.194 | 1.000 |
| 18 | 0.140 | 0.140 | 0.789 | 1.000 |
| 24 | 0.620 | 0.620 | 0.967 | 1.000 |
| 36 | 0.985 | 0.985 | 1.000 | 1.000 |
| ≥60 | 1.000 | 1.000 | 1.000 | 1.000 |

**Nhận xét (B5 ≡ B2).** Ở mọi mức, đối với lưu lượng benign IPID đa dạng, FPR của combined bằng đúng FPR của volume-only. Nghĩa là trên loại traffic hợp lệ hiện thực, entropy và unique_ratio không thêm bất kỳ lớp bảo vệ nào - cổng volume là thứ duy nhất điều khiển false positive. B4 (unique-only) tự nó chặn ~100% benign (IPID hợp lệ vốn gần như unique) nên vô dụng một mình.

### 3.5 Lợi ích của cải tiến: giảm false positive so với Rℓ2 gốc

Đây là điểm mấu chốt của E1 — **Rℓ2 cải tiến giảm bao nhiêu false positive so với Rℓ2 gốc** (`random2048`):

| samples/window | 5 | 12 | 18 | 24 | 36 | 60 | 120 | 300 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| FPR Rℓ2 GỐC (chặn mọi frag) | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| FPR Rℓ2 CẢI TIẾN (B5) | 0.000 | 0.001 | 0.140 | 0.620 | 0.985 | 1.000 | 1.000 | 1.000 |

- **Ở tải fragment hợp lệ thấp (≤ 12 mẫu/cửa sổ):** Rℓ2 cải tiến flag ~0% trong khi Rℓ2 gốc flag 100%. Đây chính là **giá trị nhóm mang lại** — không ép mọi phản hồi phân mảnh hợp lệ sang TCP. Testbed thật hiện chạy ~5–6 mẫu/cửa sổ, nằm trọn trong vùng này, nên cải tiến gần như xoá sạch FP không cần thiết.
- **Ở tải cao (60 – ~1400):** bản cải tiến thoái hoá về đúng hành vi gốc (FPR → 1.0). Tức lợi ích chỉ có trong **miền tải phân mảnh hợp lệ thấp–vừa**.

Với nguồn IPID nghèo (`smallpool16`), cải tiến giữ FPR = 0 ở **mọi** tải (cổng unique_ratio không mở). (Cái giá của cải tiến — để lọt attack tải thấp/low-entropy — được đo ở E2.)

### 3.6 Luật cải tiến là BAND-PASS, không phải high-pass: vùng mù ở tải rất cao

Lưới tải chuẩn của outline dừng ở 300 mẫu/cửa sổ, nên nếu chỉ nhìn Bảng 1 sẽ kết luận nhầm rằng "tải càng cao thì càng chặn". Mở rộng lưới cho thấy điều ngược lại (`random2048`, K = 20 run/mức):

| samples/window | 600 | 1200 | 1400 | **1600** | 1800 | 2000 | 3000 | 6000 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| FPR Rℓ2 cải tiến (B5) | 1.000 | 1.000 | 1.000 | **0.299** | **0.000** | **0.000** | **0.000** | **0.000** |
| FPR chỉ-volume (B2) | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| `unique_ratio` | 0.871 | 0.759 | 0.724 | 0.693 | 0.664 | 0.641 | 0.524 | 0.324 |
| `entropy` | 8.94 | 9.70 | 9.85 | 9.97 | 10.07 | 10.16 | 10.44 | 10.73 |

**Cơ chế.** Dải IPID chỉ có 2048 giá trị. Khi cửa sổ chứa đủ nhiều mảnh, **va chạm IPID là tất yếu** → `unique_ratio` tụt xuống dưới ngưỡng 0.70 → cổng AND **đóng lại** → luật ngừng chặn. Vậy luật cải tiến chỉ chặn trong một **dải giữa** (khoảng 18 → ~1400 mẫu/cửa sổ); dưới và **trên** dải đó nó đều không chặn, trong khi luật chỉ-volume vẫn chặn.

**Vì sao điều này quan trọng.** Attack thật trong testbed chạy ở **~2038 mẫu/cửa sổ** (max 2418, đo từ `artifacts/r2entropy/attack-on`) — tức **gấp ~7 lần** mức cao nhất mà lưới chuẩn thử, và nằm ngay cạnh vùng mù này. Đây là cơ sở cho đường né mạnh nhất tìm được, đo ở **E2 §3.7** (`attack_dup_sweep`): kẻ tấn công chỉ cần **gửi mỗi IPID hai lần** — vẫn phủ đủ 100% dải IPID nên xác suất poison không đổi — là `unique_ratio ≈ 0.5 < 0.70` và luật cải tiến **không chặn gì cả**, trong khi Rℓ2 gốc vẫn chặn.

Do đó **không được phát biểu "tải càng cao thì bản cải tiến càng chặn"**; phát biểu đúng là: bản cải tiến chỉ hoạt động trong một dải tải hữu hạn.

---

## 4. Diễn giải (theo "Quy tắc diễn giải kết quả" của outline)

### 4.0 Bảng tóm tắt: số liệu → nhận định

Mỗi dòng là một con số đo được và điều nó chứng minh (nguồn `random2048` — đúng model `auth_server.py`):

| Số liệu đo được | Nhận định rút ra |
| --- | --- |
| Rℓ2 gốc: FPR = **1.000** ở cả 8 mức tải | Luật gốc ép **mọi** phản hồi phân mảnh hợp lệ sang TCP → đây là chi phí mà cải tiến muốn cắt |
| Cải tiến: FPR = **0.000** tại 5 mẫu/cửa sổ (CP 95% `[0, 0.00061]`) và **0.001** tại 12 (CP `[0.0006, 0.0026]`) | **Cải tiến đạt mục tiêu**: ở tải thấp gần như xoá sạch báo động nhầm. Testbed thật chạy ~5–6 mẫu → nằm trọn trong vùng này |
| Cải tiến: FPR = **0.140** tại 18 (CI `[0.098, 0.182]`, cận dưới > 0) | **Điểm bắt đầu hỏng**: false positive xuất hiện có ý nghĩa thống kê từ 18 |
| Cải tiến: FPR = **0.620** tại 24 (CI `[0.558, 0.682]`) | Ngay **tại chính ngưỡng thiết kế 24**, cứ 3 phản hồi hợp lệ thì ~2 bị chặn nhầm |
| Cải tiến: FPR = **0.985** (36) → **1.000** (60–300) | Từ 36 trở lên cải tiến **mất hết lợi ích**, hành xử y như luật gốc |
| Cải tiến: FPR = **0.299** (1600) → **0.000** (1800–6000), trong khi chỉ-volume vẫn **1.000** | **Vùng mù**: trên ~1600 luật **ngừng chặn hoàn toàn** (§3.6) — luật là band-pass |
| `blocks_combined == blocks_volume` ở **160/160 run** | Ba cổng thu về **đúng một cổng volume**; entropy + unique_ratio không đóng góp gì trên benign |
| `smallpool16`: cải tiến FPR = **0.000** mọi mức, trong khi chỉ-volume = **0.556** (24), **1.000** (≥60) | Đây là **chỗ duy nhất** cổng unique_ratio thực sự có ích — nhưng lệch khỏi threat model |

### 4.1 Bốn nhận định chi tiết

1. **Vùng an toàn (safe operating range) = tải ≤ 12 mẫu/cửa sổ.** Với **mọi** kiểu nguồn, FPR ≈ 0 (Clopper–Pearson cận trên ≤ **0.0026**). Testbed thật hiện chạy ~5–6 mẫu/cửa sổ → **nằm trong vùng an toàn**. Hệ quả quan trọng: số liệu benign cũ "0 false positive" **đúng nhưng không chứng minh được gì** về hành vi ở tải cao — vì detector chưa bao giờ bị đẩy ra khỏi vùng an toàn.

2. **Failure boundary = 18 → 24.** Với nguồn IPID đa dạng (`random2048` và `sequential`, tức chính model của `auth_server.py`), false positive xuất hiện có ý nghĩa thống kê **từ mức 18** (random 0.140, sequential 0.167 — CI cận dưới > 0) và **bùng nổ ngay tại ngưỡng thiết kế 24** (random **0.620**, sequential **0.563**). Từ 36 trở lên chặn gần như toàn bộ (0.985 → 1.000). Theo đúng quy tắc của outline: *"nếu benign FPR tăng mạnh ở tải hợp lệ thì coi đó là failure boundary; không tuyên bố phân biệt tổng quát."*

3. **Entropy/unique_ratio KHÔNG thêm gì so với chỉ đếm số lượng.** `B5 ≡ B2` ở mọi mức, và đây là **đẳng thức cấu trúc chính xác**, không phải trùng hợp thống kê: `blocks_combined == blocks_volume` ở **160/160 run** (bit-identical). Cơ chế: với IPID đa dạng, hễ `samples ≥ 24` thì `entropy ≥ log₂24 ≈ 4.58 > 4.0` và `unique_ratio ≈ 0.994 > 0.70` — **cả hai cổng mở tầm thường**, nên luật AND thu về đúng cổng volume. Nói cách khác, **một resolver hợp lệ nhưng bận trông y hệt một flood** dưới con mắt entropy/unique_ratio. Đây là lý do bắt buộc phải chạy **E2** (kiểm ở cùng volume).

4. **Cổng unique_ratio chỉ có ích ở đúng một chỗ — và chỗ đó lệch threat model.** Với nguồn IPID nghèo (`smallpool16`), chỉ-volume sẽ báo nhầm nặng (**0.556** tại 24; **1.000** từ 60) nhưng cổng `unique_ratio` chặn lại → cải tiến giữ FPR = **0.000** ở mọi mức. Tức tín hiệu này giúp **tránh FP cho nguồn IPID lặp** (NAT/thiết bị nghèo) — nhưng kẻ tấn công thì **cần** IPID đa dạng để dò trúng, nên lợi ích này không nằm trên hướng đe dọa chính.

5. **Luật là band-pass, không phải high-pass — và attack thật nằm sát vùng mù.** Trên ~1600 mẫu/cửa sổ, va chạm IPID trong dải 2048 giá trị kéo `unique_ratio` xuống dưới 0.70 (1600: **0.693**; 2000: **0.641**; 6000: **0.324**) → cổng AND đóng → FPR về **0.000** trong khi chỉ-volume vẫn **1.000**. Attack thật trong testbed chạy ở **~2038 mẫu/cửa sổ** (max 2418) — tức **ngay trong/ cạnh vùng mù**. Đây là điểm yếu nghiêm trọng nhất mà E1 phát hiện, và nó bị bỏ sót nếu chỉ chạy đúng lưới ≤ 300 của outline.

**Kết luận RQ1:** So với Rℓ2 gốc (chặn mọi fragment, FPR = 100%), Rℓ2 cải tiến của nhóm **giảm mạnh false positive ở tải fragment hợp lệ thấp** (`≲ 12` mẫu/cửa sổ → FPR ≈ 0) — đây là lợi ích thật, và trùng đúng miền tải mà testbed thật đang chạy. Tuy nhiên bộ ngưỡng `24 / 4.0 / 0.70` chỉ an toàn trong miền đó: vượt ngưỡng 24, với nguồn IPID đa dạng, bản cải tiến chặn nhầm ~62% và thoái hoá về hành vi gốc (~100%) trong dải 60–1400. Và như §3.6 chỉ ra, **trên ~1600 mẫu/cửa sổ luật lại ngừng chặn hoàn toàn** — luật là band-pass, tạo ra một vùng mù mà kẻ tấn công khai thác được (E2 §3.7). Việc chọn ngưỡng để mở rộng miền an toàn *và* đóng vùng mù này thuộc **E3**.

---

## 5. Threats to Validity

- **External validity (E5 chưa chạy).** Testbed là mô phỏng dựa trên `dnslib` shim + marker FRAG1/IPID + arrival Poisson; **chưa** có Unbound/BIND, IP fragmentation thật hay PCAP replay. Vì vậy **không** dùng các cụm "deployment-ready", "real-world robust", "production-grade". Con số FPR tuyệt đối có thể đổi theo phân phối tải và mô hình IPID thật.
- **Construct validity.** "Tốc độ" được điều khiển bằng target samples/window qua Poisson, không phải qua inter-query của client thật + `AUTH_DELAY`; và mọi FRAG2 benign đến từ một `src_ip` (đúng cách detector key theo `(src_ip, dst_ip)`). Đây là trừu tượng steady-state có kiểm soát, phù hợp để dựng đường biên, nhưng là một trừu tượng.
- **Metric hệ thống bị hoãn.** Latency/throughput/CPU không đo trong mô phỏng (cần Docker) - sẽ bổ sung khi chạy ma trận Docker/E5.
- **Phạm vi ngưỡng.** E1 chỉ đánh giá operating point `24/4.0/0.70`; việc chọn ngưỡng đúng đắn (train/validation/held-out) thuộc **E3**.

---

## 6. Việc E1 dẫn tới (next steps)

| Ưu tiên | Hạng mục | E1 đã cung cấp gì |
| --- | --- | --- |
| P1 | Baseline/ablation B0–B5 | Đường FPR–rate có CI + preview B2/B3/B4 trên benign |
| **P2** | **E2 volume-matched** | E1 cho thấy `B5 ≡ B2` trên benign đa dạng -> **bắt buộc** E2 để biết entropy có tách được benign/attack khi **cùng volume** không |
| P3 | E3 chọn ngưỡng | E1 chỉ ra `24` đặt ngay trên vùng FPR bùng nổ -> cần chọn lại ngưỡng trên validation, đánh giá held-out |
| P4 | E4 thống kê | Protocol K=20 + run-level/CP CI đã áp dụng ở đây, tái dùng cho E2/E3 |
| P5 | E5 gần thực tế | Hạ claim xuống controlled-emulation cho tới khi có Unbound/BIND |

---

## 7. Kiểm định độc lập (adversarial audit)

E1 đã qua một vòng **audit đối kháng đa góc nhìn** (4 lens độc lập: thống kê, fidelity mô phỏng, tính đúng của code, kiểm chứng claim - mỗi lens đọc mã/dữ liệu thật và tái tạo số, sau đó một vòng verify đối kháng cố bác bỏ từng phát hiện).

**Kết luận audit: "mostly valid" - 0 lỗi phải sửa (must-fix).** Các điểm được xác nhận độc lập:

- **Tái lập bit-for-bit:** chạy lại mô phỏng bằng chính seed của harness cho `random2048 @ samples/window=24` ra **3721/6000 = 0.6202**, đúng bằng `e1_results.json`. Một lần chạy độc lập 200 run với seed mới ra **0.6179** -> biên ~0.62 **không** phụ thuộc seed.
- **Fidelity thật:** harness import đúng `shannon_entropy` + `r2_should_block` từ `resolver.py` (không cài lại) và mirror đúng `_prune` (`resolver.py:162-164`).
- **`B5 ≡ B2` là cấu trúc:** block-count combined vs volume **bit-identical trong toàn bộ 200 run** kiểm chứng - không phải near-tie ngẫu nhiên.
- **Thống kê hợp lệ:** đúng đơn vị độc lập (run); t-interval run-level + cluster bootstrap + Clopper–Pearson được tam giác hoá; `smallpool16` FPR=0 nhất quán với cơ chế cổng unique_ratio.

**Ba tinh chỉnh (should-fix) đã áp dụng vào báo cáo này:** (1) làm rõ occupancy thực ≈ N+1 và thêm cột occupancy vào Bảng 1 (Ghi chú 1); (2) nêu rõ Clopper–Pearson/bootstrap là CI chính cho cell gần 0/gần 1 vì t-interval có thể ra ngoài [0,1] (Ghi chú 2); (3) phát biểu `B5 ≡ B2` như một cơ chế (đẳng thức chính xác 0/160 run), không phải trùng hợp (§4.3).

Không có phát hiện nào làm thay đổi kết luận RQ1.

---

## 8. Phụ lục tái lập (Reproducibility)

**Chạy lại toàn bộ E1:**

```bash
cd Code/research/Report/experiments/E1
python e1_experiment.py --runs 20 --decisions 300   # sinh CSV/JSON/notes
python e1_plot.py                                    # sinh figures/Figure_1.png, Figure_2.png
```

**Cấu hình khoá (P0 logging - đã ghi trong `e1_results.json > meta`):**

- Operating point: `min_samples=24, entropy_threshold=4.0, unique_ratio_threshold=0.70, window=2.0s`
- Levels: `[5, 12, 18, 24, 36, 60, 120, 300]` · Behaviors: `[random2048, sequential, smallpool16]`
- K = 20 runs/cell · 300 decisions/run · `experiment_seed = 20260805` (thứ tự cell + seed mỗi cell suy ra xác định)
- Detector source: `labs/r2entropy/resolver/resolver.py` (import trực tiếp) · commit `5086e45`
- FPR = benign `tc_block` / decisions (ghi rõ tử số/mẫu số cho từng run trong `e1_runs.csv`)

**Tệp sản phẩm:**

| Tệp | Nội dung |
| --- | --- |
| `e1_experiment.py` | Harness E1 (import detector thật) |
| `e1_plot.py` | Sinh Figure_1, Figure_2 |
| `e1_runs.csv` | 480 dòng - một dòng/run: blocks, decisions, FPR mỗi variant, entropy, unique_ratio, **seed** |
| `e1_levels.csv` | Tổng hợp theo (behavior, level, variant) + run-CI + Clopper–Pearson |
| `e1_results.json` | Toàn bộ kết quả + `meta` (config, provenance, timestamp) |
| `notes.txt` | Mô tả + tóm tắt số liệu |
| `figures/Figure_1.png` | FPR(rate) - failure boundary |
| `figures/Figure_2.png` | entropy(rate) & unique_ratio(rate) - cơ chế |

---

*Báo cáo sinh từ dữ liệu run `20260806_215941`. Mọi số trong bài truy ngược được về `e1_results.json` / `e1_runs.csv`.*
