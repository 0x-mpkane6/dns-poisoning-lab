# E2 — Volume-matched benign vs attack (Sức phân biệt độc lập của entropy/unique_ratio)

**Đề tài:** Đánh giá và cải tiến cơ chế phát hiện DNS Cache Poisoning dựa trên POPS — Rℓ₂ cải tiến theo entropy IPID
**Thí nghiệm:** E2 (ưu tiên **P2**) — đóng **RQ2** (confounding volume)
**Ngày chạy:** 2026-08-05 · **Detector commit:** `1c32ef1`
**Phạm vi kết luận:** Testbed **controlled emulation** (chưa E5). Không suy rộng thành hiệu quả thực tế.

**Kết quả then chốt.** Ở cùng volume, entropy và unique_ratio không thêm bất kỳ sức phân biệt nào so với volume-only: B5 (combined) = B2 (volume-only) trên mọi mức và mọi high-entropy attack (paired margin = `0.000 [0.000, 0.000]`). Tệ hơn, trước attack fixed-IPID (entropy thấp), B5 bị né hoàn toàn (TPR = 0) trong khi B2 vẫn bắt được — nghĩa là phần "cải tiến entropy" khiến detector kém đi. Theo đúng quy tắc diễn giải của outline: "nếu B5 không vượt B2, không bảo vệ claim entropy-based; đổi framing hoặc sửa detector trước khi nộp."

---

## 1. Câu hỏi và mục tiêu

> **RQ2 — Entropy/unique_ratio có sức phân biệt ĐỘC LẬP khi benign và attack có CÙNG volume không?**
> *Bằng chứng cần có:* so sánh tại nhiều mức volume; ablation và CI của chênh lệch hiệu năng (PR-AUC, FPR tại cùng TPR, paired 95% CI).

---

## 2. Phương pháp

### 2.1 Detector và cửa sổ (đúng như E1)

Import trực tiếp `shannon_entropy` + `r2_should_block` từ [`resolver.py`](../../../../labs/r2entropy/resolver/resolver.py); cửa sổ trượt Poisson (λ = level/2.0 s) prune đúng như `R2EntropyTable._prune`. Operating point B5: `samples ≥ 24, entropy ≥ 4.0, unique_ratio ≥ 0.70`, window 2.0 s.

### 2.2 Điều kiện (1 benign + 4 attack), **cùng volume**

Mọi điều kiện sinh cửa sổ ở **cùng samples/window**. Mô hình IPID của attacker lấy đúng từ [`spoof_r2entropy.py`](../../../../labs/r2entropy/attacker/scripts/spoof_r2entropy.py):

| Điều kiện | Lớp | Mô hình IPID | Vai trò |
| --- | --- | --- | --- |
| `benign` | negative | Uniform{0..2047} (auth model) | nền so sánh |
| `attack_sweep` | positive | quét 0..2047 tuần hoàn (`ATTACK_VARIANT=random`) | **flood thật, continuous** |
| `attack_random` | positive | Uniform{0..2047} (giả ngẫu nhiên) | worst case: **giống hệt benign** |
| `attack_fixed` | positive | IPID = 777 cố định (`ATTACK_VARIANT=fixed`) | **adaptive / né entropy** |
| `attack_bursty` | positive | sweep, arrival bursty (2×/0.5× luân phiên) | **bursty** |

Vì attacker spoof `src=AUTH_IP`, FRAG2 giả rơi **cùng bucket `(src,dst)`** với benign → cửa sổ attack là **hỗn hợp** benign + attacker (tham số `benign_frac`, mặc định 0.1). Tổng occupancy ≈ level ở mọi điều kiện → **volume được match**.

### 2.3 Tải, lặp, thống kê

- **Matched-volume levels:** samples/window ∈ **{24, 60, 120, 200}** (outline khuyến nghị).
- **K = 20 runs/cell**, 150 decision-window/run, thứ tự cell randomize, seed mỗi cell ghi log.
- **Metric:** benign block = **FPR**; attack block = **TPR**. Ablation B2–B5.
- **PR-AUC** (attack = positive, benign = negative, prevalence 0.5): sweep từng tín hiệu đơn làm score (volume = samples, entropy, unique_ratio) → *average precision*. PR-AUC ≈ 0.5 nghĩa tín hiệu **vô dụng** (bằng ngẫu nhiên).
- **FPR tại cùng TPR (=0.95)** cho từng tín hiệu.
- **Paired 95% CI:** hiệu (margin) giữa B5 và B2 của đại lượng `TPR_attack − FPR_benign`, **ghép theo seed**.

**Chú thích phương pháp (kế thừa từ audit E1).** E2 dùng lại nguyên cơ chế cửa sổ + thống kê đã được audit độc lập ở E1 ("mostly valid", 0 must-fix). Hai lưu ý áp dụng luôn cho E2: (i) occupancy — "samples/window = N" là tải mục tiêu Poisson; occupancy trung bình thực ≈ N + ~1 (ví dụ level 24 → `samples_mean` ≈ 24.8, xem §3.4) vì sự kiện vừa đến được tính trong cửa sổ của chính nó; (ii) CI — với block-rate gần 0/gần 1, ưu tiên Clopper–Pearson/bootstrap; t-interval chỉ là phụ.

---

## 3. Kết quả

### 3.1 Hình 1 — Ở cùng volume, TPR vs FPR của detector B5

![Figure 1 — TPR vs FPR at matched volume](figures/Figure_1.png)

*High-entropy attack (sweep/random/bursty) nằm **trên đường chéo** TPR = FPR → detector không phân biệt được, chỉ đang phản ứng theo volume. `attack_fixed` rơi xuống **TPR = 0** (bị né). Kích thước điểm = samples/window.*

### 3.2 Bảng 1 — TPR (attack) vs FPR (benign) và margin B5−B2

FPR benign và TPR attack của **B5 (combined)**, cùng **paired margin B5−B2** (95% CI). Tất cả ở cùng volume.

| Điều kiện | s/win | FPR benign (B5) | TPR attack (B5) | TPR attack (B2) | Paired **B5−B2** margin (95% CI) |
| --- | ---: | ---: | ---: | ---: | :-- |
| `attack_sweep` | 24 | 0.611 | 0.587 | 0.587 | **+0.000** [+0.000, +0.000] |
| `attack_sweep` | 60 | 1.000 | 1.000 | 1.000 | **+0.000** [+0.000, +0.000] |
| `attack_sweep` | 120 | 1.000 | 1.000 | 1.000 | **+0.000** [+0.000, +0.000] |
| `attack_sweep` | 200 | 1.000 | 1.000 | 1.000 | **+0.000** [+0.000, +0.000] |
| `attack_random` | 24 | 0.611 | 0.570 | 0.570 | **+0.000** [+0.000, +0.000] |
| `attack_random` | 60–200 | 1.000 | 1.000 | 1.000 | **+0.000** [+0.000, +0.000] |
| `attack_bursty` | 24 | 0.611 | 0.819 | 0.819 | **+0.000** [+0.000, +0.000] |
| `attack_bursty` | 60–200 | 1.000 | 1.000 | 1.000 | **+0.000** [+0.000, +0.000] |
| **`attack_fixed`** | 24 | 0.611 | **0.000** | 0.587 | **−0.587** [−0.668, −0.506] |
| **`attack_fixed`** | 60 | 1.000 | **0.000** | 1.000 | **−1.000** [−1.000, −1.000] |
| **`attack_fixed`** | 120 | 1.000 | **0.000** | 1.000 | **−1.000** [−1.000, −1.000] |
| **`attack_fixed`** | 200 | 1.000 | **0.000** | 1.000 | **−1.000** [−1.000, −1.000] |

**Đọc bảng:**

- Với high-entropy attack, **TPR = FPR** ở mọi mức (ví dụ level 24: benign FPR 0.611 vs attack TPR 0.587 — thậm chí benign còn bị chặn *nhiều hơn*; level ≥ 60: cả hai = 1.0 → detector **chặn tất cả**, thành một "chuông báo volume").
- Paired **B5 − B2 = 0.000** với CI **[0, 0]** → entropy + unique_ratio **không đóng góp gì** ngoài cổng volume.
- Với **`attack_fixed`**, B5 TPR = **0** (entropy = 0 < 4.0 → cổng entropy đóng vĩnh viễn) trong khi B2 vẫn TPR cao → margin âm mạnh, CI **không chứa 0**.

### 3.3 Hình 2 — Vì sao: PR-AUC ≈ ngẫu nhiên & phân phối entropy chồng lấn

![Figure 2 — PR-AUC and entropy overlap](figures/Figure_2.png)

- **(a)** PR-AUC(entropy) ≈ PR-AUC(volume) ≈ **0.5** cho sweep/random/bursty → cả entropy lẫn volume đều **không** tách được hai lớp ở cùng volume. (Cột `fixed` PR-AUC entropy = 1.0 là "tách hoàn hảo nhưng **ngược chiều**" — xem mục 4.3.)
- **(b)** Phân phối entropy per-window tại samples/window = 120: `benign`, `sweep`, `random`, `bursty` **chồng lấn** quanh 6.8–7.1 bit, tất cả **cao hơn nhiều** cổng 4.0. Chỉ `fixed` nằm ~0.7 bit (dưới cổng). → Không có ranh giới entropy nào tách benign khỏi high-entropy attack.

### 3.4 Bảng 2 — Ablation benign FPR ở cùng volume (điều kiện `benign`)

Cho thấy các cổng đơn còn **tệ hơn** trên benign:

| s/win | B5 combined | B2 volume | B3 entropy-only | B4 unique-only |
| ---: | ---: | ---: | ---: | ---: |
| 24 | 0.611 | 0.611 | **0.966** | **1.000** |
| ≥60 | 1.000 | 1.000 | 1.000 | 1.000 |

B3 (entropy-only) chặn nhầm 96.6% benign ngay ở level 24; B4 (unique-only) chặn nhầm 100%. → không cổng nào trong ba tín hiệu tự nó là bộ phân biệt tốt ở tải này.

### 3.5 Kiểm tra độ vững (sensitivity) của phát hiện `attack_fixed`

Evasion của `attack_fixed` **vững** khi thay đổi tỉ lệ trộn benign trong cửa sổ attack:

| `benign_frac` | B5 TPR (fixed, level 24) | B2 TPR (fixed, level 24) |
| ---: | ---: | ---: |
| 0.0 | 0.000 | 0.749 |
| 0.25 | 0.000 | 0.746 |
| 0.50 | 0.006 | 0.637 |

Ngay cả khi **một nửa** cửa sổ là traffic benign thật, IPID cố định vẫn ghì entropy xuống dưới 4.0 → B5 vẫn miss.

---

## 4. Diễn giải (theo "Quy tắc diễn giải kết quả" của outline)

### 4.1 Entropy **không** vượt volume-only ⇒ không bảo vệ được claim entropy-based

Paired B5 − B2 = `0.000 [0.000, 0.000]` ở **mọi** mức volume cho **mọi** high-entropy attack. PR-AUC(entropy) ≈ PR-AUC(volume) ≈ chance. Đây là kết luận trực tiếp cho RQ2: **ở cùng volume, entropy/unique_ratio không có sức phân biệt độc lập**. Toàn bộ khả năng "phân biệt" của detector đến từ cổng volume — đúng như nghi ngờ confounding. Theo quy tắc: *không che giấu; đổi framing sang rate/volume-based hoặc sửa cơ chế rồi chạy lại protocol.*

### 4.2 Ở cùng volume, detector trở thành "chuông báo volume"

Với samples/window ≥ 60, **TPR = FPR = 1.0**: detector chặn cả benign lẫn attack như nhau. Nó không phân biệt lớp — chỉ phản ứng khi volume vượt ngưỡng. Kết hợp với E1 (benign ở tải cao bị chặn nhầm ~100%), bức tranh nhất quán: **ngưỡng volume làm toàn bộ công việc; entropy/unique là dư thừa**.

### 4.3 Trước attack thích nghi (fixed-IPID), entropy làm detector **kém đi**

`attack_fixed` phơi bày giả định ngầm của thiết kế: "*attack thì entropy cao*". Một attacker chỉ cần dùng **một IPID cố định** (vẫn flood đủ volume để poison) là entropy = 0 < 4.0 → cổng entropy của B5 **đóng** → **TPR = 0**, né hoàn toàn. Trong khi đó B2 (volume-only) vẫn bắt được (samples ≥ 24). Margin B5 − B2 = −0.59 đến −1.00.

Lưu ý sắc thái về "PR-AUC entropy = 1.0" của `fixed`: entropy tách hoàn hảo hai lớp (benign entropy cao ~7, fixed ~0), nhưng theo chiều ngược với luật đã triển khai. Detector dùng "entropy ≥ 4.0 ⇒ nghi ngờ", nên nó gắn cờ benign (entropy cao) và bỏ sót fixed attack (entropy thấp). Nói cách khác, entropy có thông tin, nhưng luật hiện tại dùng sai chiều — và không có một ngưỡng entropy đơn hướng nào vừa bắt được cả sweep (cao) lẫn fixed (thấp).

### 4.4 Hệ quả cho bài

- **Không** được giữ framing "entropy-based improvement" như một bộ phân biệt benign/attack độc lập với volume — E2 bác bỏ điều đó ở mức paired-CI.
- Lựa chọn trung thực: (a) **đổi framing** thành cơ chế rate/volume-based (và thừa nhận entropy/unique chỉ giúp tránh FP cho nguồn IPID nghèo — không phải threat model); hoặc (b) **thiết kế lại detector** (ví dụ: mô hình IPID theo từng nguồn, phát hiện *bất thường hai phía* gồm cả entropy quá thấp lẫn quá cao, hoặc đặc trưng khác biệt thật giữa benign và forged fragment) rồi chạy lại E1–E4.

---

## 5. Threats to Validity

- **External validity (E5 chưa chạy):** cùng giới hạn như E1 — `dnslib` shim, marker IPID, arrival Poisson; chưa có Unbound/BIND, fragmentation thật, PCAP. Không dùng "deployment-ready/real-world/production-grade".
- **Mô hình commingling:** cửa sổ attack trộn benign theo `benign_frac`; đã kiểm định độ vững ở {0, 0.25, 0.5}. Tỉ lệ thật phụ thuộc tải nền và cường độ flood.
- **Định nghĩa TPR trong lab:** ở lab này, khi `defense_on`, resolver **không** merge forged fragment (poison chỉ xảy ra ở B0). Do đó E2 đo phân biệt ở **mức quyết định của detector** (block window attack vs benign) thay vì ASR cuối — đúng mục tiêu "cô lập sức phân biệt". ASR đầy đủ thuộc B0/E5 trên topology Docker.
- **Tách biệt fragile của sweep ở volume rất cao:** PR-AUC(entropy) của sweep tăng nhẹ tới ~0.78 ở level 200 vì sweep không có va chạm IPID (unique_ratio = 1.0 tuyệt đối) còn benign random có vài va chạm. Đây là **artifact mong manh** (attacker chỉ cần dùng `random` là xoá) và **detector triển khai không khai thác** nó (B5 ≡ B2). Không nên coi là bằng chứng cho entropy.

---

## 6. Việc E2 dẫn tới

| Ưu tiên | Hạng mục | E2 kết luận / bàn giao |
| --- | --- | --- |
| P2 | **RQ2 confounding** | **Đóng:** entropy/unique không vượt volume ở cùng volume; B5 ≡ B2; B5 bị fixed-attack né. |
| P3 | **E3 chọn ngưỡng** | Vì entropy/unique vô ích ở cùng volume, E3 nên tập trung biện minh **ngưỡng volume** (min_samples) trên validation/held-out, và kiểm tra liệu có operating point nào cứu được claim entropy không (dự báo: không). |
| P1 | E1 | Nhất quán: benign tải cao ↔ attack cùng volume có cùng (entropy, unique). |
| P4 | E4 | Protocol K=20 + paired CI đã áp dụng. |
| — | **Sửa cơ chế** | Cân nhắc phát hiện hai phía (entropy quá thấp *và* quá cao) hoặc đặc trưng phân biệt thật; nếu không, hạ đóng góp xuống "volume/rate-based detection". |

---

## 7. Phụ lục tái lập

```bash
cd Code/research/Report/experiments/E2
python e2_experiment.py --runs 20 --windows 150 --benign-frac 0.1   # CSV/JSON/notes
python e2_plot.py                                                    # figures/Figure_1.png, Figure_2.png
```

**Cấu hình khoá (đã ghi trong `e2_results.json > meta`):** operating point `24/4.0/0.70`, window 2.0 s; levels `{24,60,120,200}`; conditions `{benign, attack_sweep, attack_random, attack_fixed, attack_bursty}`; K=20 runs × 150 windows; `benign_frac=0.1`; `experiment_seed=20260805`; detector `resolver.py` commit `1c32ef1`; attacker model `spoof_r2entropy.py`.

| Tệp | Nội dung |
| --- | --- |
| `e2_experiment.py` · `e2_plot.py` | Harness (import detector thật) + vẽ hình |
| `e2_windows.csv` | Mọi decision-window: samples, entropy, unique_ratio, block/variant |
| `e2_summary.csv` | TPR/FPR theo (condition, level, variant) + CI |
| `e2_results.json` | Toàn bộ + PR-AUC, FPR@TPR, paired margin + meta/provenance |
| `figures/Figure_1.png` | TPR vs FPR ở cùng volume (B5 trên đường chéo) |
| `figures/Figure_2.png` | PR-AUC entropy≈volume + chồng lấn phân phối entropy |
