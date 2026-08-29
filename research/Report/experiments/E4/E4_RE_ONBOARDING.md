# E4 RE-ONBOARDING — Tổng hợp độ ổn định và khoảng tin cậy của E1–E3

**Mục đích:** đưa thành viên tiếp quản vào đúng phạm vi E4. E4 là lớp kiểm chứng/thống kê áp dụng xuyên E1–E3 theo Outline, **không** phải một threshold sweep, không phải held-out test mới, và không được dùng để cải thiện hoặc chọn lại kết quả E3.

**Trạng thái đầu vào khi viết tài liệu này (2026-08-29):**

- E1 confirmatory validator: `PASS` 18/18.
- E2 canonical confirmatory validator: `PASS` 18/18.
- E3 final independent validator: `PASS` 12/12; lock validator: `PASS` 9/9.
- E3 threshold `8/6.0/0.90` đã khóa trước test và held-out test đã chạy đúng một lần. Không mở lại test để retune.

---

## 1. E4 trong Outline thực sự làm gì?

Outline định nghĩa E4 là **“Độ ổn định và khoảng tin cậy”** và nói rõ đây là protocol thống kê xuyên E1–E3, không phải thí nghiệm tùy chọn tách biệt.

E4 phải làm bốn việc:

1. Chuẩn hóa cách đọc metric và đơn vị độc lập của E1, E2, E3.
2. Tổng hợp mean/median và 95% CI theo run hoặc paired trace; với tail latency, dùng bootstrap theo run/hierarchical bootstrap, không coi packet/window phụ thuộc là IID.
3. Báo paired effect size và CI giữa B5 với các baseline ở nơi pairing thực sự tồn tại; p-value chỉ là phụ, không thay effect size/CI.
4. Lập bảng coverage để chỉ ra metric nào đã đo, chưa đo, và claim nào được/không được phép đưa vào bài.

E4 **không** được làm các việc sau:

- Chạy lại 60 candidate grid, đổi selection criterion hoặc đổi `8/6.0/0.90`.
- Mở/re-score held-out E3 nhằm chọn threshold khác, loại failure probe xấu, hoặc cherry-pick cell đẹp.
- Gọi synthetic attack-alert là ASR, poisoning prevention hoặc endpoint attack outcome.
- Điền ASR, latency, throughput, CPU, memory, PR-AUC hay p-value nếu input không đo chúng.
- Gộp E2 và E3 thành hai dataset độc lập rồi tính một “meta-analysis” chung: E3 repartition từ canonical E2 decisions nên hai nguồn không độc lập.

---

## 2. Kết luận hiện có và ý nghĩa cho E4

| Thí nghiệm | Bằng chứng đã có | Điều E4 cần giữ nguyên |
| --- | --- | --- |
| E1 | FPR benign thay đổi mạnh theo rate/IPID; boundary khoảng 18–24 samples/window; low-diversity pattern có thể không trigger. | Đơn vị độc lập là run; không coi 300 decisions/run là 300 mẫu IID. Không suy ra attack coverage/ASR từ E1. |
| E2 | Old B5 `24/4.0/0.70` có $\Delta J=0$ so với B2 trên primary sweeps; fixed/duplicate probes là failure cases. | Pair là đơn vị độc lập; CI 95% từ 5.000 paired bootstrap. TPR/FPR ở đây là synthetic detector rates. |
| E3 | Candidate lock `8/6.0/0.90` có held-out macro $\Delta J=+0.0108$, CI 95% $[+0.0079;+0.0138]$ vs B2, nhưng FNR tăng và failure probes vẫn âm mạnh ở level cao. | Test chỉ được xem là held-out của candidate đã khóa; không diễn giải lợi ích nhỏ này thành production-ready hoặc ASR improvement. |

**Điểm phương pháp bắt buộc:** E2 và E3 không phải hai replication độc lập. E3 lấy canonical E2 decision dataset rồi repartition theo paired trace 60/20/20. E4 có thể đặt hai kết quả cạnh nhau để giải thích evolution từ point cũ sang point lock, nhưng phải ghi rõ chúng có nguồn dữ liệu chung và không pooling CI/p-value giữa chúng.

---

## 3. Canonical input được phép dùng

Chỉ dùng artifact xác nhận dưới đây. Không dùng thư mục `provisional`, `smoke`, historical run hoặc source working tree như bằng chứng thay thế artifact đã freeze.

| Scope | Artifact chính | Evidence integrity |
| --- | --- | --- |
| E1 | `research/Report/experiments/E1/runs/E1_confirmatory_20260810_seed20260810_raw_v2/` | `validation.json` PASS 18/18 |
| E2 | `research/Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/` | `validation.json` PASS 18/18 |
| E3 | `research/Report/experiments/E3/` | `e3_validation.json` PASS 12/12; `e3_lock_validation.json` PASS 9/9 |

E4 phải snapshot trong manifest ít nhất hash của các file sau trước khi tổng hợp:

```text
E1: e1_protocol.json, e1_results.json, e1_runs.csv, validation.json
E2: e2_protocol.json, e2_results.json, e2_summary.csv, validation.json
E3: e3_protocol.json, split_manifest.json, e3_validation_grid.json,
    e3_locked_threshold.json, e3_lock_validation.json,
    e3_test_results.json, e3_summary.csv, e3_validation.json
```

Đọc raw/run-level artifact chỉ khi cần tái tính CI đã định nghĩa; ưu tiên dùng frozen aggregate/result đã được validator xác nhận. E4 không được sửa các artifact upstream.

---

## 4. Metric dictionary và đơn vị độc lập

| Metric | E1 | E2 | E3 | Đơn vị / cách xử lý đúng |
| --- | --- | --- | --- | --- |
| Benign trigger / synthetic FPR | Có | Có | Có | E1: independent run. E2/E3: paired trace/run, không phải window. |
| Synthetic attack-alert / TPR, FNR | Không phải mục tiêu E1 | Có | Có | Pair attack–benign matching; báo cùng benign-trigger và $J$. |
| $J=\text{attack-alert}-\text{benign-trigger}$ | Không phải metric chính E1 | Có | Có | Pair-level rồi macro/CI theo protocol từng experiment. |
| $\Delta J$ B5 vs baseline | Không | Có | Có | Paired difference CI; không pool E2 với E3. |
| Precision 50:50 | Không | Có | Có | Synthetic balanced class mix, không phải prevalence production. |
| PR-AUC | Không | Có, feature-level | Không phải primary combined-rule result | Không gán PR-AUC E2 cho B5 lock E3. |
| ASR / poisoning outcome | Không | Không | Không | Ghi `not measured/not supported`; không thay bằng attack-alert. |
| Latency, throughput, CPU, memory | Không đủ evidence xác nhận | Không đủ evidence xác nhận | Không đủ evidence xác nhận | Ghi `not measured`; E5/runtime campaign mới có thể đo. |
| Tail latency p95/p99 | Không có input phù hợp | Không có input phù hợp | Không có input phù hợp | Không fabricate bootstrap. Nếu sau này đo, bootstrap theo run/hierarchical. |

### Quy tắc CI

1. Giữ CI upstream nếu E4 chỉ tổng hợp; luôn ghi bootstrap unit và số resample đã dùng.
2. Nếu audit/tái tính E1: cluster bootstrap theo independent run trong cùng condition; không resample 300 decision của run như IID.
3. Nếu audit/tái tính E2/E3: resample whole paired trace bên trong cell. E2/E3 dùng 5.000 resamples; macro E3 được resample phân tầng trên tám primary cells.
4. Median/IQR chỉ báo nếu có distribution run-level thật. Không suy ngược median từ mean/CI.
5. P-value chỉ bổ sung khi pre-registered trong E4 protocol, effect size + CI vẫn là kết quả chính.

---

## 5. Câu hỏi E4 cần trả lời

E4 không trả lời “threshold nào tốt hơn?”; câu đó đã bị khóa ở E3. Nó trả lời:

1. Mỗi kết luận E1–E3 có uncertainty nào và independent unit nào?
2. Kết quả xấu/failure boundary có được báo đầy đủ hay bị che bởi macro mean?
3. Các metric bắt buộc trong Outline đã có evidence nào, metric nào còn thiếu?
4. Claim nào có thể xuất hiện trong bài mà không vượt quá controlled synthetic evidence?
5. Cần E5/runtime experiment nào để đóng external-validity và system-metric gap?

### Kết luận dự kiến hiện tại

- E1: có operating boundary benign rõ, nhưng không chứng minh security outcome.
- E2: old B5 không thêm separation so với B2 ở primary sweeps và có failure probes rõ.
- E3: locked point mới có improvement $\Delta J$ dương nhưng nhỏ trên held-out, đồng thời attack-alert giảm và failure boundary không biến mất.
- Toàn bộ chuỗi hiện chỉ hỗ trợ claim về **synthetic detector behavior trong controlled emulation**. Không hỗ trợ deployment claim, ASR claim, hay performance/overhead claim.

---

## 6. E4 protocol nên khóa trước khi chạy bất kỳ aggregation nào

Tạo `E4/e4_protocol.json` trước khi tạo summary. Protocol tối thiểu phải ghi:

```json
{
  "run_id": "E4-R001",
  "status": "registered-before-aggregation",
  "objective": "Statistical synthesis and reporting audit of frozen E1–E3 artifacts; no threshold selection or experimental rerun.",
  "allowed_inputs": ["canonical E1", "canonical E2", "validated E3"],
  "forbidden_actions": [
    "E3 validation/test resweep or threshold selection",
    "modification of upstream protocols/results/locks",
    "pooling E2 and E3 as independent samples",
    "inference of ASR or runtime metrics from detector alerts"
  ],
  "primary_reporting_unit": {
    "E1": "independent run",
    "E2": "paired trace",
    "E3": "paired trace"
  },
  "inference": {
    "confidence_interval": "95%",
    "E2_E3_bootstrap_resamples": 5000,
    "tail_latency_rule": "run-level or hierarchical bootstrap only when real per-run latency inputs exist"
  },
  "missing_metrics_policy": "report not measured/not supported; never impute"
}
```

Không tự thêm acceptance gate để gọi E3 “pass/fail” về security sau khi đã thấy kết quả. E4 report effect sizes, CI, heterogeneity và scope; nó không đổi conclusion rule của E3.

---

## 7. Kế hoạch triển khai khuyến nghị

### Bước 0 — Inventory và gate

1. Verify các validator upstream vẫn PASS và hash input khớp.
2. Viết `e4_input_manifest.json`, gồm path/hash/status/canonical role của mỗi artifact.
3. Fail fast nếu E1/E2/E3 validator fail, nếu E3 lock/test provenance không khớp, hoặc nếu input nằm ngoài canonical list.

### Bước 1 — Register protocol và preflight

1. Khóa `e4_protocol.json`.
2. Viết `e4_preflight.py` chỉ đọc manifest, protocol và frozen result/summary artifacts.
3. Kiểm tra schema/metric dictionary, units, CI method, known missing metric và overlap E2–E3 warning.
4. Xuất `e4_preflight.json` PASS/FAIL; không đọc raw data nếu chưa cần audit CI.

### Bước 2 — Build summary có traceability

Viết `e4_summarize.py` để tạo:

```text
E4/
├── e4_input_manifest.json
├── e4_preflight.json
├── e4_summary.csv              # one row per experiment × condition × metric
├── e4_paired_effects.csv       # ΔJ/paired CI của E2 và E3, giữ separate
├── e4_coverage_matrix.csv      # measured / not measured / unsupported
├── e4_summary.json             # provenance + structured equivalent
└── figures/
    ├── e4_effect_sizes.png     # forest-style: E2 vs E3, không pooling
    ├── e4_failure_boundaries.png
    └── e4_metric_coverage.png
```

Mỗi row phải có `source_experiment`, `source_artifact`, `source_hash`, `metric`, `scope`, `condition`, `level`, `estimate`, `ci95_low`, `ci95_high`, `independent_unit`, `inference_method`, `measurement_status`.

### Bước 3 — Statistical audit (nếu cần)

Chỉ tạo `e4_ci_audit.py` khi E4 cần xác minh CI từ run/pair-level input. Script phải replay đúng method upstream, so khớp result freeze, và fail nếu không khớp. Không được đổi bootstrap seed/replicate để tìm CI đẹp hơn.

### Bước 4 — Report và validator E4

1. `e4_plot.py` chỉ vẽ từ E4 summary frozen.
2. `E4_report.md` dẫn nguồn rõ, không pooling E2/E3 và có Threats to Validity/coverage table.
3. `e4_validate.py` kiểm tra hashes, coverage, CI provenance, absence of threshold modification, and absence of E2/E3 statistical pooling.
4. E4 chỉ hoàn tất khi validator PASS; report không được overwrite report upstream.

---

## 8. Figures/tables nên đưa vào E4

| Output | Nội dung | Cảnh báo diễn giải |
| --- | --- | --- |
| Forest/effect-size plot | E2 old B5 vs B2 và E3 new B5 vs B2/old B5, CI 95%, tách panel/nguồn. | Không vẽ pooled estimate E2+E3. |
| Failure-boundary plot | E1 benign boundary + E2/E3 fixed/duplicate probes, với scope label rõ. | Không đồng nhất benign FPR với synthetic attack failure. |
| Metric coverage matrix | Có/không có TPR, FPR, $J$, PR-AUC, ASR, latency, throughput, CPU, memory. | “Không đo” không có nghĩa bằng 0 hoặc tốt. |
| Evidence table | Claim, experiment, effect/CI, unit, scope, limitation. | Tránh claim vượt raw artifact. |

Không cần tạo ROC mới: Outline chỉ yêu cầu ROC khi sweep continuous score; E4 đang tổng hợp result đã freeze. Không có lý do hợp lệ để dựng ROC từ combined-rule binary output.

---

## 9. Lỗi/phạm vi cần tránh

1. Lấy E3 held-out rows để tune một “E4 threshold”. Đó là protocol violation.
2. Dùng CI E2 và E3 để tính một CI gộp như hai replication độc lập.
3. Gọi $\Delta J>0$ là “attack success giảm” hay “B5 an toàn hơn”.
4. Bỏ fixed/duplicate failure probes chỉ vì không nằm trong selection criterion E3.
5. Chuyển TPR/FPR synthetic sang precision theo prevalence thực tế không có dữ liệu prevalence.
6. Báo “FPR = 0” mà không chỉ rõ numerator/denominator và CI.
7. Nói latency/overhead tốt khi chưa có input runtime có timestamp/resource samples.
8. Lấy source code hiện tại để suy luận canonical run nếu hash/snapshot không khớp artifact provenance.

---

## 10. Sau E4 nên làm gì?

E4 là bước cần hoàn tất để báo cáo chuỗi E1–E3 một cách trung thực, nhưng nó không đóng external validity. Hướng tiếp theo hợp lý là **E5**, không phải retune E3:

1. Đăng ký E5 protocol/campaign mới, tách biệt hoàn toàn E3 held-out data.
2. Chạy tối thiểu một benign rate thấp, một điểm gần E1 failure boundary, một volume-matched primary attack, cùng operating point B5 cuối.
3. Dùng Unbound/BIND với IP fragmentation thật hoặc PCAP replay nếu khả thi.
4. Đo outcome end-to-end có denominator rõ: poisoning attempt/success (ASR), resolver answer/cache state, latency p50/p95/p99, throughput, CPU, memory.
5. So sánh B0–B5 bằng paired runs, K=20 cố định/configuration; nếu CI quá rộng thì tăng đồng loạt lên K=30 theo protocol.

Nếu không thể chạy E5, bài vẫn có thể trình bày E1–E4 như **controlled-emulation proof of concept**, nhưng Threats to Validity phải ghi rõ thiếu fragmentation/resolver thật và mọi system/security outcome.

---

## 11. Checklist trước khi gọi E4 hoàn tất

- [ ] Chỉ canonical E1/E2 và validated E3 xuất hiện trong manifest.
- [ ] Hash/status validator upstream được kiểm tra và ghi lại.
- [ ] E4 protocol được khóa trước aggregation.
- [ ] E1 dùng run-level unit; E2/E3 dùng paired-trace unit.
- [ ] Không pool E2/E3 như independent studies.
- [ ] $\Delta J$, CI, failure probes và limitation đều được report, kể cả bất lợi.
- [ ] ASR/system metric thiếu được ghi `not measured/not supported`, không suy diễn.
- [ ] E3 selected threshold, lock và upstream results không bị sửa.
- [ ] E4 validator PASS và report/figure trace về E4 summary artifact.

---

## 12. File nên đọc trước khi viết code E4

1. `research/draft/Outline_thuc_nghiem_bo_sung_dieu_chinh.docx` — mục E4, metric, đơn vị phân tích và rules diễn giải.
2. `research/Report/experiments/E1/E1_report.md` — benign operating boundary và CI run-level.
3. `research/Report/experiments/E2/E2_report.md` — volume-matched, ablation, feature PR-AUC và paired CI.
4. `research/Report/experiments/E3/E3_report.md` — validation lock, held-out result và failure boundaries mới.
5. `research/Report/experiments/E3/e3_protocol.json` và `e3_validation.json` — prohibited actions/provenance của E3.
6. Các artifact canonical liệt kê ở mục 3 — nguồn số liệu, không dùng report prose thay cho JSON/CSV khi build summary.
