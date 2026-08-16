# E2 — Volume-matched benign vs attack của rule Rℓ2 ba biến

**Run ID:** `E2_confirmatory_20260814_complete_b0_ablation`  
**Trạng thái kiểm tra:** `PASS`  
**Phạm vi:** mô phỏng có kiểm soát theo thời điểm query. Đây không phải thí nghiệm IP fragment thật; không đo poisoning, ASR, độ trễ, CPU hay hiệu năng triển khai.

## Mục tiêu

Rule đề xuất B5 block khi đồng thời đạt ba điều kiện trong cửa sổ 2 giây: số FRAG2, entropy Shannon của IPID và tỉ lệ IPID khác nhau. B1 là POPS/Rℓ2 gốc; B2, B3 và B4 lần lượt là ablation volume-only, entropy-only và unique-only.

E2 đánh giá khả năng phân biệt của các cấu hình này khi benign và attack có cùng volume. Phân tích chính so sánh B5 với B2; các so sánh B5 với B1–B4 được báo cáo kèm khoảng tin cậy ghép cặp.

## Thiết kế volume-matched benign vs attack

- Có 20 lần chạy độc lập cho mỗi ô kết quả chính (test), mỗi lần 150 lần chấm điểm.
- Mỗi benign/attack pair dùng chung hoàn toàn thời điểm FRAG2 và thời điểm query. Vì vậy số mẫu trong từng cửa sổ là như nhau; khác biệt nếu có chỉ đến từ IPID/origin chứ không phải tải.
- B0 là cấu hình không phòng vệ; B1 là rule POPS/Rℓ2 gốc; B2–B4 là các ablation; B5 là rule ba biến.
- Trước test có một split kiểm tra generator và một split validation riêng. Test không được dùng để chọn ngưỡng hay chỉnh tốc độ.
- Mỗi run giữ raw JSONL: event FRAG2, IPID, origin, timestamp, feature và các quyết định của biến thể rule. Validator đã đọc lại toàn bộ raw và tính lại các số trong bảng.
- Hai mẫu so sánh chính là sweep IPID liên tục và sweep IPID theo đợt; IPID random là đối chứng. Fixed và duplicate là failure probe độ đa dạng IPID thấp, không phải kết quả poisoning/ASR.
- Chưa có biến thể adaptive/high-entropy; không suy diễn kết quả thành khả năng né detector của đối thủ thật.

## Cách đọc số

- **Benign bị bật**: rule bật trên traffic benign control. Số thấp hơn là tốt hơn về mặt tránh TC/TCP không cần thiết.
- **B1** là baseline POPS/Rℓ2 gốc; **B5** là rule ba biến; **B2–B4** là các ablation một biến.
- **Condition attack bị bật**: rule bật trong condition stress tổng hợp. Đây chỉ là detector alert rate, **không phải** tỉ lệ ngăn poisoning thành công.
- **J** = condition attack bị bật − benign bị bật. J càng cao thì rule càng tách được hai condition trong mô phỏng này.
- **ΔJ (B5−baseline)** dương nghĩa là B5 tách tốt hơn baseline; âm nghĩa là kém hơn. Khoảng 95% được bootstrap theo run pair.
- **Synthetic TPR/FNR/FPR** mô tả detector trên cặp condition tổng hợp, không phải poisoning/ASR. Precision là giá trị dưới tỷ lệ lớp 50:50 của thiết kế ghép cặp.
- Bảng score-level chọn ngưỡng trên validation để đạt TPR mục tiêu 0,95, sau đó báo cáo TPR/FPR/precision và PR-AUC trên test duy nhất.

## Kết quả

### Sweep IPID liên tục

ΔJ trung bình = +0.000, CI 95% [+0.000, +0.000]. Trong phép ablation B5–B2 này, hai rule gần như tương đương trong biên ±0,05 đã đăng ký trước.

| Tải | B2: benign bị bật | B2: condition attack bị bật | B5: benign bị bật | B5: condition attack bị bật | ΔJ (B5−B2), 95% CI |
|---:|---:|---:|---:|---:|---:|
| 24 | 0.510 | 0.510 | 0.510 | 0.510 | 0.000 [0.000, 0.000] |
| 60 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 [0.000, 0.000] |
| 120 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 [0.000, 0.000] |
| 200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 [0.000, 0.000] |

![Hình 1. J của B2 và B5 trên các sweep chính](figures/Figure_1_net_separation.png)

### Sweep IPID theo đợt

ΔJ trung bình = +0.000, CI 95% [+0.000, +0.000]. Trong phép ablation B5–B2 này, hai rule gần như tương đương trong biên ±0,05 đã đăng ký trước.

| Tải | B2: benign bị bật | B2: condition attack bị bật | B5: benign bị bật | B5: condition attack bị bật | ΔJ (B5−B2), 95% CI |
|---:|---:|---:|---:|---:|---:|
| 24 | 0.494 | 0.494 | 0.494 | 0.494 | 0.000 [0.000, 0.000] |
| 60 | 0.999 | 0.999 | 0.999 | 0.999 | 0.000 [0.000, 0.000] |
| 120 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 [0.000, 0.000] |
| 200 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 [0.000, 0.000] |

### Phân phối entropy và unique ratio

Phân phối được tổng hợp trên toàn bộ decision event của held-out test, theo profile và mức volume.

![Hình 3. Phân phối entropy và unique ratio trên test volume-matched](figures/Figure_3_feature_distributions.png)

### Baseline/ablation B0–B5 ở ngưỡng đã đăng ký

| Tải | Biến thể | Synthetic TPR | Synthetic FNR | Synthetic FPR | Precision cân bằng | J |
|---:|---|---:|---:|---:|---:|---:|
| 24 | B0 — Không phòng vệ | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| 24 | B1 — Rℓ2 gốc | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 24 | B2 — volume-only | 0.510 | 0.490 | 0.510 | 0.500 | 0.000 |
| 24 | B3 — entropy-only | 0.953 | 0.047 | 0.950 | 0.501 | 0.002 |
| 24 | B4 — unique-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 24 | B5 — combined | 0.510 | 0.490 | 0.510 | 0.500 | 0.000 |
| 60 | B0 — Không phòng vệ | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| 60 | B1 — Rℓ2 gốc | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 60 | B2 — volume-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 60 | B3 — entropy-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 60 | B4 — unique-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 60 | B5 — combined | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 120 | B0 — Không phòng vệ | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| 120 | B1 — Rℓ2 gốc | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 120 | B2 — volume-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 120 | B3 — entropy-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 120 | B4 — unique-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 120 | B5 — combined | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 200 | B0 — Không phòng vệ | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 |
| 200 | B1 — Rℓ2 gốc | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 200 | B2 — volume-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 200 | B3 — entropy-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 200 | B4 — unique-only | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |
| 200 | B5 — combined | 1.000 | 0.000 | 1.000 | 0.500 | 0.000 |

### Paired delta của B5 so với từng baseline

#### Sweep liên tục

| B5 so với | ΔJ trung bình qua 4 mức tải, CI 95% | Diễn giải đăng ký trước |
|---|---:|---|
| B1 — Rℓ2 gốc | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |
| B2 — volume-only | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |
| B3 — entropy-only | -0.001 [-0.001, 0.000] | practical_equivalence_within_registered_margin |
| B4 — unique-only | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |

#### Sweep theo đợt

| B5 so với | ΔJ trung bình qua 4 mức tải, CI 95% | Diễn giải đăng ký trước |
|---|---:|---|
| B1 — Rℓ2 gốc | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |
| B2 — volume-only | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |
| B3 — entropy-only | -0.001 [-0.002, -0.001] | practical_equivalence_within_registered_margin |
| B4 — unique-only | 0.000 [0.000, 0.000] | practical_equivalence_within_registered_margin |

### PR-AUC và FPR tại TPR mục tiêu

Các ngưỡng scalar bên dưới được khóa trên validation để đạt tỷ lệ alert attack ít nhất 0,95; bảng chỉ dùng held-out test để đánh giá. Đây là phân tích feature-level, không thay đổi ngưỡng B5 đã đăng ký.

| Tải | Score | Ngưỡng khóa từ validation | PR-AUC | TPR test | FPR test | Precision cân bằng |
|---:|---|---:|---:|---:|---:|---:|
| 24 | Volume | 15.000 | 0.500 | 0.969 | 0.969 | 0.500 |
| 24 | Entropy | 3.907 | 0.514 | 0.968 | 0.967 | 0.500 |
| 24 | Unique ratio | 1.000 | 0.530 | 0.973 | 0.863 | 0.530 |
| 60 | Volume | 48.000 | 0.500 | 0.963 | 0.963 | 0.500 |
| 60 | Entropy | 5.585 | 0.550 | 0.960 | 0.944 | 0.504 |
| 60 | Unique ratio | 0.983 | 0.666 | 0.939 | 0.605 | 0.610 |
| 120 | Volume | 103.000 | 0.500 | 0.954 | 0.954 | 0.500 |
| 120 | Entropy | 6.681 | 0.618 | 0.945 | 0.891 | 0.515 |
| 120 | Unique ratio | 0.983 | 0.888 | 0.927 | 0.269 | 0.777 |
| 200 | Volume | 177.000 | 0.500 | 0.957 | 0.957 | 0.500 |
| 200 | Entropy | 7.447 | 0.726 | 0.958 | 0.851 | 0.530 |
| 200 | Unique ratio | 0.976 | 0.992 | 0.980 | 0.053 | 0.950 |

![Hình 4. FPR tại TPR mục tiêu của các score đơn biến](figures/Figure_4_validation_locked_tpr_fpr.png)

### Kết quả âm: IPID cố định và IPID lặp

- `attack_random_continuous` là negative control: IPID random có thể giống benign về phân phối.
- `attack_fixed_continuous` và `attack_dup_sweep_continuous` là failure probe của detector: chúng chỉ cho biết rule bật hay không trong dòng IPID tổng hợp. Không được suy ra ASR, BFrag coverage hay poisoning success.

| Tải | B2 bật ở fixed/duplicate | B5 bật ở fixed/duplicate | ΔJ fixed, 95% CI | ΔJ duplicate, 95% CI |
|---:|---:|---:|---:|---:|
| 24 | 0.510 | 0.000 | -0.510 [-0.545, -0.470] | -0.510 [-0.545, -0.472] |
| 60 | 1.000 | 0.000 | -1.000 [-1.000, -1.000] | -1.000 [-1.000, -1.000] |
| 120 | 1.000 | 0.000 | -1.000 [-1.000, -1.000] | -1.000 [-1.000, -1.000] |
| 200 | 1.000 | 0.000 | -1.000 [-1.000, -1.000] | -1.000 [-1.000, -1.000] |

Trong hai probe này B5 không bật, còn B2 vẫn bật; ΔJ của B5 âm tại mọi mức volume. Kết quả này được báo cáo như failure case của operating point `24/4,0/0,70`.

![Hình 2. Hiệu ứng bổ sung của B5 so với B2](figures/Figure_2_delta_B5_minus_B2.png)

### Phân tích bổ sung: PR-AUC/AUPRC của tín hiệu liên tục

| Tải | Volume | Entropy | Tỷ lệ IPID khác nhau |
|---:|---:|---:|---:|
| 24 | 0.500 | 0.514 | 0.530 |
| 60 | 0.500 | 0.550 | 0.666 |
| 120 | 0.500 | 0.618 | 0.888 |
| 200 | 0.500 | 0.726 | 0.992 |

Ở sweep liên tục tải 200, unique ratio đạt AUPRC cao trong khi B2 và B5 vẫn có cùng quyết định. Operating point `24/4,0/0,70` vì vậy chưa khai thác được khoảng cách score này.

## Điều E2 chưa thể kết luận

E2 không cho thấy B5 vượt B2 ở operating point `24/4,0/0,70` trên hai sweep chính. Kết luận về hiệu quả end-to-end so với POPS/Rℓ2 gốc cần E1/E5 với IP fragmentation thật, resolver thật, TC→TCP đầy đủ, và các metric ASR/latency/CPU.

## File để kiểm tra lại

- `e2_protocol.json`: thiết kế đã khóa trước khi chạy.
- `e2_runs.csv`, `e2_decisions.csv.gz`, `raw_runs/`: số liệu gốc theo run/event.
- `e2_results.json`, `e2_summary.csv`: tổng hợp chỉ từ test split.
- `validation.json`: kết quả kiểm tra raw → bảng; phải là PASS trước khi dùng báo cáo này.
