> Cập nhật: hai phần IPID benign–attack và orphan baseline đã hoàn tất trong bộ v2. Xem `followups/KET_QUA_VA_HUONG_DAN.md` trong ZIP; số liệu và phạm vi của phần benign-only bên dưới vẫn giữ nguyên.

# Kết quả chỉnh hình và bổ sung từ log

Bộ chính giữ RQ1 với hai hình. Các hình dùng font tối thiểu 8,5 pt khi in rộng 122 mm; bảng LaTeX dùng 9 pt. Đã kiểm tra PDF vector, font thực tế, giới hạn khung và biên dịch riêng bảng để phát hiện tràn dòng. Đây là bộ file để đưa lên Cloud, không phải bản thảo đã chỉnh trên Cloud.

## Các bước thay trong Cloud

1. Upload bốn file PDF `RQ1_benign_boundary`, `RQ1_volume_matched_discrimination`, `RQ2_threshold_calibration`, `RQ3_failure_modes` vào thư mục `figure/`. Có PNG cùng tên nếu cần.
2. Dùng `figure_blocks.tex` để thay bốn figure block; giữ nguyên label tham chiếu. Hình 3 chỉ còn PR-AUC. Hình 4 chỉ còn panel A (60 ô trong một heatmap) và panel B (held-out).
3. Bỏ figure block runtime cũ, chèn nội dung `RQ4_runtime_outcomes.tex`. Dùng câu mô tả mechanism trong `text_replacements.tex`; không cần chèn thêm bảng mechanism nếu đang giới hạn trang.
4. Chèn bảng benign-cost ứng với campaign đang trình bày. Bảng `original` là dữ liệu cũ; bảng `factorial` là campaign 2x2 đã hoàn thành. Không gộp hai campaign để tính CI.
5. Câu Delta J = 0 và giải thích H <= log2(n) đã có trong RQ text được cung cấp. Giữ/thay câu theo `text_replacements.tex`, không thêm lặp lại.
6. Table 1 hiện là bảng định nghĩa B0–B5. Chỉ bỏ nếu cần tiết kiệm trang; đoạn thay thế đã giữ đủ cả B0 và B1–B5. Chưa thể xác nhận 12 trang nếu chưa cập nhật bản Cloud.

## Bảng chi phí benign

Các tỷ lệ dùng 20 run × 50 trial mỗi ô. Median/p95 là phân vị mô tả của 1.000 query attempts, gồm timeout, không gồm cache probe. Chúng không phải trung bình các p95 từng run. CSV có cả hai cách tổng hợp để tránh nhầm. Native-drop dùng lịch concurrent nên không quy toàn bộ chênh lệch latency cho policy.

### Campaign cũ

| Policy | Benign workload | TC % | TCP retry % | Median ms | p95 ms | No-answer % |
|---|---|---:|---:|---:|---:|---:|
| B0_OFF | BENIGN_LOW | 0.0 | 0.0 | 334.3 | 361.2 | 0.8 |
| B0_OFF | BENIGN_BOUNDARY | 0.0 | 0.0 | 336.9 | 363.2 | 0.4 |
| B1_RL2_TC | BENIGN_LOW | 100.0 | 100.0 | 376.0 | 409.7 | 0.7 |
| B1_RL2_TC | BENIGN_BOUNDARY | 100.0 | 100.0 | 380.5 | 420.2 | 1.3 |
| B5_LOCKED_TC | BENIGN_LOW | 0.0 | 0.0 | 334.2 | 363.4 | 0.7 |
| B5_LOCKED_TC | BENIGN_BOUNDARY | 0.0 | 0.0 | 337.0 | 365.0 | 0.3 |
| RFC_DROP_NATIVE | BENIGN_LOW | 0.0 | 0.0 | 2010.5 | 2022.1 | 100.0 |
| RFC_DROP_NATIVE | BENIGN_BOUNDARY | 0.0 | 0.0 | 2010.7 | 2021.7 | 100.0 |

### Campaign 2x2, IPID sweep

| Policy | Benign workload | TC % | TCP retry % | Median ms | p95 ms | No-answer % |
|---|---|---:|---:|---:|---:|---:|
| B0_OFF | BENIGN_DIVERSE_MODERATE | 0.0 | 0.0 | 337.8 | 363.2 | 0.2 |
| B0_OFF | BENIGN_DIVERSE_HIGH | 0.0 | 0.0 | 340.8 | 367.3 | 0.1 |
| B1_RL2_TC | BENIGN_DIVERSE_MODERATE | 100.0 | 100.0 | 378.6 | 412.0 | 0.4 |
| B1_RL2_TC | BENIGN_DIVERSE_HIGH | 100.0 | 100.0 | 399.0 | 428.1 | 0.5 |
| B5_LOCKED_TC | BENIGN_DIVERSE_MODERATE | 0.0 | 0.0 | 338.1 | 364.1 | 0.3 |
| B5_LOCKED_TC | BENIGN_DIVERSE_HIGH | 100.0 | 100.0 | 398.6 | 434.2 | 0.7 |
| RFC_DROP_NATIVE | BENIGN_DIVERSE_MODERATE | 0.0 | 0.0 | 2010.2 | 2021.3 | 100.0 |
| RFC_DROP_NATIVE | BENIGN_DIVERSE_HIGH | 0.0 | 0.0 | 2011.1 | 2021.6 | 100.0 |

Ở B5, benign diverse 200/s có TC và TCP retry 100%, median/p95 398,6/434,2 ms, no-answer 0,7%; tại 12/s lần lượt là 0%, 338,1/364,1 ms và 0,3%. Đây là chi phí quan sát, không tự chứng minh mọi timeout do detector gây ra.

## Boundary B5 locked

Đã kiểm tra hash và score initial của 480 run / 144.000 quyết định benign gốc, rồi score lại locked (8, 6, 0.90). Ở target 60 fragments/window, locked có trigger 19,37% với random IPID và 32,28% với sequential; tại 120, cả hai đạt 100%. Target load là kỳ vọng, không phải occupancy từng cửa sổ; vì vậy có thể trigger ở target 60 dù gate thực tế đòi n >= 64.

Câu đề xuất:

> Since H <= log2(n), the locked rule requires at least 64 fragments per two-second window together with high IPID diversity (U >= 0.90); at n = 64, all identifiers must be distinct to attain H = 6.

Không thay rule đầy đủ bằng điều kiện n >= 64 và U >= 0.90: hai điều kiện này chưa bảo đảm H >= 6 ở mọi n. Locked boundary là post-hoc rescoring, không phải một held-out evaluation mới.

## Những phần bổ sung có sẵn hoặc đã chạy thêm

- Runtime 2x2: đã có 320 run / 16.000 trial hợp lệ; đã xuất bảng 16 ô riêng, không chạy lại.
- Lưới H = 7/8, U = 0.95/0.99: đã có trong E3-Extend; kiểm chứng lại 8/8 PASS, chỉ validation. Bảng rút gọn `validation_sensitivity_posthoc.tex` giữ đủ attack-alert, benign-trigger, FNR và Delta J.
- IPID 65.536: đã chạy bổ sung **benign controlled sensitivity** ở `controlled_ipid_sensitivity/`. Tái dựng khớp 480 run gốc / 144.000 quyết định; thay không gian IPID và giữ lịch đến/occupancy khớp ở mọi quyết định. Có thêm 144.000 quyết định mới.

Với random IPID, tại target 600, B5 locked có trigger 0% trong không gian 2.048 và 100% trong không gian 65.536. Trong replay 65.536, trigger vẫn 100% đến target 6.000. Việc rule ngừng trigger ở tải cao vì collision phụ thuộc vào không gian IPID giả định. Kết quả này chỉ là benign sensitivity; không bổ sung bằng chứng attack PR-AUC, malicious answers hay cache insertion cho controlled traces.

## Còn chưa triển khai

- Orphan-fragment ratio baseline: đã bổ sung bằng offline replay PCAP runtime trong bộ v2; không phải một policy đã enforce. Xem báo cáo followups.
- Công khai GitHub và đặt link: chưa commit/push, do đang chờ giải quyết chỉ dẫn trước đó không commit/push. Không có link artifact mới được công bố để chèn vào bài.

Nguồn, số liệu CSV, script và kiểm chứng có trong cùng bộ. `final_verification.json` kiểm tra font/kích thước, hash 811 nguồn và numerator no-answer từ 16.000 benign trials.
