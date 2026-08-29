# E4 — Độ ổn định, khoảng tin cậy và phạm vi bằng chứng của E1–E3

> **Bản dùng để chép vào báo cáo.** E4 là statistical synthesis đọc các artifact freeze của E1, E2 và E3. E4 không chạy lại experiment, không chọn lại threshold, không mở raw E3 held-out decision data và không thay đổi bất kỳ kết quả upstream nào.

## 1. Vai trò của E4

Theo Outline, E4 là protocol thống kê xuyên E1–E3: chuẩn hóa đơn vị độc lập, khoảng tin cậy (CI), paired effect và metric coverage. Nó không trả lời “ngưỡng nào tốt hơn?” vì E3 đã khóa candidate `8/6.0/0.90` trước held-out test.

E4 chỉ tổng hợp controlled-emulation evidence:

- E1: benign operating boundary theo rate/IPID behavior.
- E2: volume-matched synthetic attack–benign separation cho old B5 `24/4.0/0.70`.
- E3: validation-locked, one-time held-out evaluation cho new B5 `8/6.0/0.90`.

`attack-alert`, `benign-trigger`, TPR/FPR tổng hợp và $J$ là metric của detector trong điều kiện tổng hợp. Chúng không phải ASR, poisoning success, resolver outcome hoặc deployment performance.

## 2. Input integrity và đơn vị phân tích

E4 input manifest xác nhận 17 artifact canonical/freeze. E1 validator đạt `PASS` 18/18, E2 validator `PASS` 18/18, E3 final validator `PASS` 12/12 và E3 lock validator `PASS` 9/9.

| Nguồn | Đơn vị độc lập | Quy mô cần giữ khi diễn giải | Inference kế thừa |
| --- | --- | --- | --- |
| E1 | Independent run | 20 run/cell | Cluster bootstrap theo run |
| E2 canonical test | Paired trace | 20 pair/cell | 5.000 whole-pair bootstrap resamples |
| E3 held-out repartition | Paired trace | 6 pair/primary cell, 8 primary cells | 5.000 stratified paired-trace bootstrap resamples |

E2 và E3 **không** là hai replication độc lập: E3 repartition canonical E2 decision dataset theo 60/20/20. Vì vậy E4 đặt hai kết quả cạnh nhau để mô tả evolution từ old B5 đến candidate lock, nhưng không pool mean, CI hay p-value giữa chúng.

Hai CSV E3 được Git checkout với LF trong khi final validator đã hash byte CRLF. E4 kiểm tra equivalence hẹp: chỉ khi đổi LF → CRLF khớp chính xác hash frozen mới được chấp nhận. Bảy artifact E3 còn lại khớp byte-for-byte; nội dung metric không bị đổi.

## 3. Paired effects E2 và E3

![Hình 1. Paired effect size và CI 95% của E2 và E3, báo riêng.](figures/e4_effect_sizes.png)

*Hình 1. Mỗi điểm là $\Delta J$; thanh ngang là CI paired bootstrap 95%. Xanh dương là E2 canonical test, xanh lá là E3 held-out repartition. Hai nguồn được tách riêng và không có pooled estimate.*

**Cách đọc và ý nghĩa Hình 1.**

- Trong E2, old B5 so với B2 (`volume`) có $\Delta J=0$ cho cả sweep continuous và bursty, CI 95% `[0; 0]`. So với B1/B4 cũng bằng 0; so với entropy-only B3 chỉ âm khoảng `−0.0006` (continuous) và `−0.0013` (bursty). Mọi E2 macro effect nằm trong biên tương đương thực tiễn $\pm0.05$ đã đăng ký của E2.
- Trong E3, new B5 so với B2 có held-out macro $\Delta J=+0.0108$, CI 95% `[+0.0079; +0.0138]`; so với old B5 cũng `+0.0108`, CI `[+0.0078; +0.0137]`.
- CI E3 dương cho thấy hướng cải thiện detector separation của candidate đã khóa được tái lập trên held-out E3. Tuy nhiên effect tuyệt đối nhỏ; biên $\pm0.05$ trong hình là criterion E2, **không** phải hard gate được áp hồi tố cho E3.

| Source | So sánh primary macro | Estimate $\Delta J$ | CI 95% | Diễn giải đúng phạm vi |
| --- | --- | ---: | ---: | --- |
| E2 | Old B5 − B2, continuous | 0.0000 | [0.0000; 0.0000] | Không có thêm separation tại point cũ. |
| E2 | Old B5 − B2, bursty | 0.0000 | [0.0000; 0.0000] | Không có thêm separation tại point cũ. |
| E3 | New B5 − B2, held-out macro | +0.0108 | [+0.0079; +0.0138] | Cải thiện synthetic separation nhỏ, không phải security outcome. |
| E3 | New B5 − old B5, held-out macro | +0.0108 | [+0.0078; +0.0137] | New point tách tốt hơn old point trong E3 scope. |

## 4. Operating boundary và failure probes

![Hình 2. E1 benign boundary và E2/E3 failure probes.](figures/e4_failure_boundaries.png)

*Hình 2. Panel trái là benign trigger rate E1; hai panel phải là synthetic failure-probe $\Delta J$ của E2/E3. Ba panel dùng metric và scope khác nhau, nên được đặt cạnh nhau để thấy boundary/failure, không dùng để tạo một average chung.*

**Cách đọc và ý nghĩa Hình 2.**

- E1 cho thấy B5 cũ trigger benign tăng rất nhanh với `random2048` và `sequential`: khoảng 10% quanh level 18, khoảng 50% ở 24, gần 100% từ 36 trở lên. `smallpool16` vẫn gần 0 vì entropy/unique ratio không đạt threshold. Đây là benign operating boundary, không phải attack coverage.
- E2 old B5 failure probes fixed-IPID và duplicate-sweep có $\Delta J\approx-0.510$ tại 24 và `−1.000` từ 60 trở lên. Rule cũ không giữ được synthetic attack alert trong các condition low-diversity này.
- E3 new B5 cải thiện failure boundary ở level 24 và 60: $\Delta J=0$ tại 24, `−0.2689` tại 60. Nhưng failure vẫn rất nặng ở 120–200: gần `−1.0` trong cả fixed-IPID lẫn duplicate-sweep.

Kết quả này loại trừ claim rằng new B5 “robust” với IPID low-diversity. Việc E3 có primary macro dương không xóa failure cells; E4 giữ chúng trong kết luận thay vì chỉ báo macro mean.

## 5. Coverage metric và bằng chứng còn thiếu

![Hình 3. Metric-evidence coverage của E1–E3.](figures/e4_metric_coverage.png)

*Hình 3. Xanh lá là metric đã đo; vàng là không phải metric chính/không áp dụng; đỏ là chưa đo hoặc không được hỗ trợ. “Measured” vẫn chỉ có nghĩa evidence tồn tại trong controlled emulation.*

**Cách đọc và ý nghĩa Hình 3.**

- E1–E3 có evidence cho benign trigger/FPR tổng hợp; E2/E3 có synthetic attack-alert, FNR, balanced precision, $J$ và paired $\Delta J$.
- E2 có PR-AUC cho các continuous feature; không được chuyển PR-AUC đó thành PR-AUC của locked binary combined rule E3.
- ASR/poisoning success, latency p50/p95/p99, throughput, CPU và memory đều thiếu evidence end-to-end. Không có ô “measured” nào cho phép gọi detector là deployment-ready hoặc chứng minh B5 giảm poisoning success.

## 6. Đánh giá tổng hợp E4

E4 xác nhận ba nhận định có thể báo cáo:

1. **Boundary benign là thật và phụ thuộc IPID behavior.** E1 có run-level evidence rằng benign trigger thay đổi mạnh theo rate; không có một safe range tổng quát độc lập với behavior.
2. **Old B5 không vượt B2 ở primary volume-matched E2.** CI paired effect bằng 0 trên hai primary sweeps, trong khi failure probes âm lớn.
3. **New B5 E3 cải thiện $J$ nhỏ nhưng có trade-off.** Held-out E3 có $\Delta J$ dương, nhưng attack-alert giảm cùng benign-trigger, FNR tăng, và failure probes ở volume cao chưa được giải quyết.

E4 không biến các kết quả này thành một claim lớn hơn. Đặc biệt, E2/E3 overlap về canonical data khiến không thể gộp chúng như hai confirmation experiments độc lập; sự khác nhau của chúng là operating point và repartition/protocol E3, không phải external replication.

## 7. Kết luận và hướng tiếp theo

Chuỗi E1–E4 hiện hỗ trợ claim hẹp sau:

> Trong controlled synthetic emulation, operating point B5 mới `8/6.0/0.90` tạo synthetic detector separation macro cao hơn B2/old B5 một lượng nhỏ trên E3 held-out, nhưng vẫn có failure boundary rõ với IPID low-diversity và chưa có evidence end-to-end về DNS cache poisoning.

Hướng tiếp theo đúng là E5/runtime validation, không phải retune E3 held-out:

1. Đăng ký campaign E5 tách biệt với E3 data.
2. Chạy Unbound/BIND với IP fragmentation thật hoặc PCAP replay.
3. Đo attempt/success có denominator rõ (ASR), resolver answer/cache state, latency p50/p95/p99, throughput, CPU và memory.
4. Giữ paired runs và K cố định; report đầy đủ cả failure conditions.

Nếu không thực hiện E5, bài chỉ nên gọi E1–E4 là controlled-emulation proof of concept và nêu explicit Threats to Validity.

## 8. Artifact E4

- [Protocol](e4_protocol.json)
- [Frozen input manifest](e4_input_manifest.json)
- [Preflight: PASS 9/9](e4_preflight.json)
- [Summary metrics](e4_summary.csv)
- [Paired effects](e4_paired_effects.csv)
- [Metric coverage](e4_metric_coverage.csv)
- [Synthesis provenance and output hashes](e4_summary.json)
- [Figure script](scripts/e4_plot.py)
