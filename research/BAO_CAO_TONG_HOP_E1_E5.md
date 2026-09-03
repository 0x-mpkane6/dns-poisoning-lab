# Báo cáo tổng hợp chuỗi thực nghiệm E1–E5

> **Trạng thái (02/09/2026):** E1, E2, E3, E4 và E5 đã có artifact
> validation tương ứng. E1–E3 là controlled synthetic emulation; E4 là tổng
> hợp thống kê offline; E5 là routed-IPS runtime validation riêng trên
> Unbound 1.26.1 với fragment IPv4 thật. E5 không pool với E1–E4 và không
> biến các kết quả này thành bằng chứng deployment-ready.

## 1. Mục tiêu chung

Chuỗi E1–E5 đánh giá rule B5 cải tiến cho cơ chế phát hiện DNS cache poisoning dựa trên POPS/Rℓ₂. Rule cũ block khi đồng thời thỏa:

$$
\text{B5}_{old} = [n\ge24] \land [H\ge4.0] \land [U\ge0.70],
$$

trong đó $n$ là số fragment trong cửa sổ, $H$ là entropy IPID và $U$ là tỷ lệ IPID khác nhau.

Mục tiêu khoa học là xem entropy/unique ratio có giúp tách benign khỏi synthetic attack tốt hơn volume-only hay không, chọn operating point mà không dùng cùng dữ liệu để chọn và đánh giá, sau đó báo cáo uncertainty đầy đủ.

## 2. Tóm tắt trạng thái

| Thí nghiệm | Vai trò | Trạng thái | Kết luận ngắn |
| --- | --- | --- | --- |
| E1 | FPR theo benign fragment rate | Hoàn tất; validator PASS 18/18 | Có operating boundary rõ, phụ thuộc mạnh vào IPID behavior. |
| E2 | Volume-matched benign vs attack, ablation | Hoàn tất; validator PASS 18/18 | Old B5 không vượt B2 ở primary sweeps và có failure probes rõ. |
| E3 | Validation selection + held-out evaluation | Hoàn tất; lock PASS 9/9, final validator PASS 12/12 | New B5 có $\Delta J$ dương nhỏ trên held-out, nhưng trade-off/FNR và failure boundary còn tồn tại. |
| E4 | Statistical synthesis E1–E3 | Hoàn tất; final validator PASS 9/9 | Chuẩn hóa CI, metric coverage và giới hạn claim; không pool E2/E3. |
| E5 | Routed-IPS runtime/Root-cause validation | Hoàn tất; pilot PASS 7/7, sanity PASS 16/16, confirmatory PASS 320/320 | B1 chặn cả hai attack workload; B5 chặn flood nhưng fixed-IPID bypass detector; RFC drop chặn poison với no-answer 100%. |

## 3. E1 — Benign operating boundary

E1 chỉ tạo benign traffic, chạy 20 independent run cho mỗi behavior × level và dùng cluster bootstrap theo run. Mục tiêu là xác định khi nào B5 bắt đầu trigger benign traffic, không phải đo attack success.

- Với `random2048` và `sequential`, benign trigger bắt đầu rõ quanh level 18, khoảng 50% ở level 24 và gần 100% từ level 36.
- Với `smallpool16`, trigger gần 0 ở toàn bộ dải chính vì entropy và/hoặc unique ratio không đạt ngưỡng.
- Vì vậy, B5 không có một safe operating range độc lập với IPID behavior. Low-diversity benign có thể ít trigger, nhưng cùng cơ chế cũng tạo một failure/bypass hypothesis cần kiểm tra bằng attack data.

![E4 synthesis của E1 benign boundary cùng E2/E3 failure probes.](Report/experiments/E4/figures/e4_failure_boundaries.png)

*Cách đọc phần E1 ở panel trái: trục dọc là benign trigger/FPR tổng hợp; đây không phải TPR attack, ASR hay bằng chứng poisoning prevention.*

## 4. E2 — Volume-matched separation và ablation

E2 ghép cặp benign/attack cùng schedule, window, burstiness và volume; chỉ mô hình IPID thay đổi. Đơn vị độc lập là paired trace, CI dùng 5.000 whole-pair bootstrap resamples.

Chỉ số chính:

$$
J=\text{synthetic attack-alert rate}-\text{benign-trigger rate},
\qquad
\Delta J=J_{B5}-J_{B2}.
$$

Kết quả chính:

- Trên sweep continuous và bursty, old B5 `24/4.0/0.70` có $\Delta J=0$ so với B2 volume-only, CI 95% `[0; 0]`.
- E2 không cung cấp bằng chứng entropy/unique ratio tạo thêm separation tại operating point cũ.
- Fixed-IPID và duplicate-sweep là failure probes: old B5 có $\Delta J\approx-0.510$ ở level 24 và `−1.000` từ level 60 trở lên.
- Unique ratio vẫn có feature-level PR-AUC cao ở volume lớn; đây là tín hiệu để E3 chọn lại operating point, không phải bằng chứng B5 cũ tốt hơn B2.

## 5. E3 — Khóa threshold và đánh giá held-out

E3 tạo repartition mới 60/20/20 từ canonical E2 decisions theo paired trace. Chỉ validation được dùng để score 60 candidate; test được mở một lần sau khi lock.

Candidate được khóa là `min_samples=8`, `entropy=6.0`, `unique_ratio=0.90`. Nó thắng theo macro $\Delta J(\text{new B5}-\text{B2})$ trên hai primary sweep × bốn level; bốn giá trị `N=8/16/24/48` tại `H=6.0,U=0.90` tie ở metric chính và tie-break chọn `N=8`.

Trên held-out E3:

| Metric macro primary | New B5 | B2 / old B5 | So sánh new B5 |
| --- | ---: | ---: | ---: |
| Attack-alert | 0.5913 | 0.8713 | Giảm 0.2800 |
| Benign-trigger | 0.5804 | 0.8713 | Giảm 0.2908 |
| FNR | 0.4088 | 0.1288 | Tăng 0.2800 |
| $J$ | 0.0108 | 0.0000 | Tăng nhỏ |
| $\Delta J$ vs B2 | — | — | +0.0108, CI 95% [+0.0079; +0.0138] |

![Paired effect E2/E3 được report riêng, không pooling.](Report/experiments/E4/figures/e4_effect_sizes.png)

*Hình cho thấy E3 $\Delta J$ dương trên held-out; điều này là cải thiện nhỏ về synthetic detector separation. Nó không có nghĩa attack success giảm, ASR giảm, hoặc rule deployment-ready.*

E3 giữ nguyên failure probes trong report: new B5 đỡ tệ hơn old B5 ở level 24/60, nhưng ở fixed-IPID và duplicate-sweep level 120–200 vẫn gần $\Delta J=-1$ so với B2.

## 6. E4 — Synthesis thống kê và phạm vi bằng chứng

E4 không chạy experiment mới. Nó hash/inventory artifact E1–E3, xác minh validator upstream, tổng hợp 703 summary rows, 70 paired-effect rows và 8 metric coverage rows. E4 final validator đạt PASS 9/9.

Điểm phương pháp quan trọng nhất: E2 và E3 dùng chung canonical decision dataset, vì E3 là repartition E2. Chúng có thể được so sánh mô tả, nhưng không phải hai replication độc lập và không được pool mean/CI/p-value.

![Metric coverage của E1–E3.](Report/experiments/E4/figures/e4_metric_coverage.png)

*Xanh là đã đo trong controlled emulation; vàng là không phải metric chính/không áp dụng; đỏ là chưa đo hoặc không được hỗ trợ.*

E4 xác nhận hiện có evidence cho detector metrics tổng hợp (benign trigger,
synthetic attack alert, FNR, $J$, paired $\Delta J$). Các metric ASR,
poisoning outcome, latency, throughput, CPU và memory chỉ xuất hiện trong E5
ở testbed runtime riêng, không phải trong dữ liệu E1–E4.

**Ghi chú provenance:** artifact E4 frozen ghi nhận final validator PASS 9/9.
Khi replay trên checkout Windows cũ, hash byte có thể lệch do CRLF; replay trong
checkout LF-normalized của cùng repository cũng đạt PASS 9/9, không mở raw
decision data và không thay đổi metric. Repository đã bổ sung quy tắc JSON dùng
LF và validator E4 tương thích Python 3.10.

## 7. E5 — Routed-IPS runtime và root-cause validation

E5 kiểm tra operating point đã khóa `N=8`, `H=6.0`, `U=0.90` trên Unbound
1.26.1 với fragment IPv4 MF/offset thật. Testbed gồm hai upstream network,
resolver, authoritative server, external attacker và một IPS/router hai
interface. IPS dùng NFQUEUE trên `FORWARD`; preflight xác nhận NFQUEUE, routing
và packet counters trước khi thu dữ liệu. Không có resolver-local poisoner.

Campaign gồm bốn policy (`B0_OFF`, `B1_RL2_TC`, `B5_LOCKED_TC`,
`RFC_DROP_NATIVE`) và bốn workload (`BENIGN_LOW`, `BENIGN_BOUNDARY`,
`ATTACK_FIXED_MATCHED`, `ATTACK_SWEEP_FLOOD`). Mỗi cell có 20 recreated-stack
runs và 50 unique-qname trials, tạo thành 320 runs và 16.000 trials. Run order
là randomized complete blocks theo seed `20260902`. Pilot đạt PASS 7/7, sanity
đạt PASS 16/16 và confirmatory đạt PASS 320/320. E5 là campaign runtime duy
nhất được giữ lại và không pool với E1–E4.

### 7.1. Kết quả confirmatory

| Policy | Workload | Attack outcome / any-poison run | Legitimate answer | No-answer | B5 trigger | Tail drop | TC / TCP retry |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| B0\_OFF | BENIGN\_LOW | — | 99,2% | 0,8% | 0% | — | — |
| B0\_OFF | BENIGN\_BOUNDARY | — | 99,6% | 0,4% | 0% | — | — |
| B0\_OFF | ATTACK\_FIXED\_MATCHED | ASR 97,5%; 20/20 | 1,6% | 0,9% | 0% | 0% | 0% / 0% |
| B0\_OFF | ATTACK\_SWEEP\_FLOOD | ASR 99,5%; 20/20 | 0% | 0,5% | 100% | 0% | 0% / 0% |
| B1\_RL2\_TC | BENIGN\_LOW | — | 99,3% | 0,7% | — | — | 100% / 100% |
| B1\_RL2\_TC | BENIGN\_BOUNDARY | — | 98,7% | 1,3% | — | — | 100% / 100% |
| B1\_RL2\_TC | ATTACK\_FIXED\_MATCHED | ASR 0%; 0/20 | 99,8% | 0,2% | 0% | 98,3% | 100% / 100% |
| B1\_RL2\_TC | ATTACK\_SWEEP\_FLOOD | ASR 0%; 0/20 | 99,2% | 0,8% | 100% | 100% | 100% / 100% |
| B5\_LOCKED\_TC | BENIGN\_LOW | — | 99,3% | 0,7% | 0% | — | — |
| B5\_LOCKED\_TC | BENIGN\_BOUNDARY | — | 99,7% | 0,3% | 0% | — | — |
| B5\_LOCKED\_TC | ATTACK\_FIXED\_MATCHED | ASR 98,0%; 20/20 | 1,6% | 0,4% | 0% | 0% | 0% / 0% |
| B5\_LOCKED\_TC | ATTACK\_SWEEP\_FLOOD | ASR 0%; 0/20 | 99,4% | 0,6% | 100% | 100% | 100% / 100% |
| RFC\_DROP\_NATIVE | BENIGN\_LOW | — | 0% | 100% | — | — | 0% / 0% |
| RFC\_DROP\_NATIVE | BENIGN\_BOUNDARY | — | 0% | 100% | — | — | 0% / 0% |
| RFC\_DROP\_NATIVE | ATTACK\_FIXED\_MATCHED | ASR 0%; 0/20 | 0% | 100% | 0% | 100% | 0% / 0% |
| RFC\_DROP\_NATIVE | ATTACK\_SWEEP\_FLOOD | ASR 0%; 0/20 | 0% | 100% | 100% | 100% | 0% / 0% |

B0\_OFF là positive control: forged tail đi qua IPS và tạo poisoning ở cả hai
attack workload. Ở flood workload, detector vẫn ghi nhận điều kiện B5 ở 100%
nhưng policy tắt nên không có enforcement; điều này xác nhận trigger và packet
verdict phải được báo cáo tách biệt.

Kết quả B5 cho thấy failure boundary nằm ở detector khi IPID có diversity thấp.
Trong `ATTACK_FIXED_MATCHED`, B5 không trigger trong 20/20 run, any-poison cũng
xảy ra ở 20/20 run và 980/1.000 trial được phân loại `detector_miss`. Trong
`ATTACK_SWEEP_FLOOD`, B5 trigger, drop forged tail, inject TC và ghi nhận TCP
retry ở 100% trial; ASR bằng 0, với 994/1.000 trial được phân loại `mitigated`
và 6 trial là `transport_failure`.

B1\_RL2\_TC chặn poisoning ở cả hai attack workload mà không phụ thuộc vào B5
detector: ASR bằng 0 và lần lượt 998/1.000 và 992/1.000 trial được phân loại
`mitigated` ở fixed-match và flood. `RFC_DROP_NATIVE` cũng chặn poisoning nhưng
gây no-answer 100% vì drop fragment mà không inject TC trong testbed này. Đây là
security--availability trade-off, không phải bằng chứng rằng drop-native là
policy phù hợp cho mọi resolver.

Trong toàn bộ confirmatory campaign, cache-before luôn miss, client exit code
đều bằng 0 và reconstruction độc lập của B5 khớp runtime trigger log. Với
20/20 any-poison run, exact 95% Clopper--Pearson interval là `[83,16%; 100%]`;
với 0/20 là `[0%; 16,84%]`. Runtime percentile, CPU/memory và raw packet/event
artifacts được lưu trong output E5 riêng.

### 7.2. Kết luận E5

E5 xác nhận routed enforcement path hoạt động: B1\_RL2\_TC và B5 khi trigger
đều drop được forged tail, inject TC và đưa resolver về TCP legitimate answer.
Failure end-to-end không được quy về detector trigger đơn thuần. Cụ thể,
fixed-IPID bypass B5 ở detector layer, flood được B5 mitigated, còn RFC native
drop đổi security protection lấy availability failure. E5 không được pool
với E1–E4.

## 8. Đánh giá tổng hợp

Chuỗi E1–E5 hỗ trợ các nhận định sau:

1. B5 behavior phụ thuộc mạnh vào rate và cấu trúc IPID; benign boundary không thể bỏ qua.
2. Operating point cũ `24/4.0/0.70` không tạo separation tốt hơn B2 trên E2 primary sweeps.
3. Operating point mới `8/6.0/0.90` cải thiện nhỏ $\Delta J$ trên E3 held-out bằng cách giảm benign trigger nhiều hơn attack alert giảm.
4. Cải thiện primary macro không xóa failure boundary low-diversity; new B5 vẫn không robust trong các synthetic fixed/duplicate probes ở volume cao.
5. E4 xác nhận giới hạn metric và sự phụ thuộc giữa E2/E3; không được coi E4 là replication mới.
6. E5 cho thấy B1\_RL2\_TC chặn được cả hai attack workload; B5 chặn được flood khi trigger nhưng fixed-IPID vẫn bypass detector, còn RFC drop-native gây no-answer 100%.

Do đó claim phù hợp là:

> Trong controlled synthetic emulation, new B5 tạo detector separation macro cao hơn B2/old B5 một lượng nhỏ ở E3 held-out; nó vẫn có failure boundary với IPID low-diversity. Runtime E5 trên Unbound 1.26.1 với routed IPS và fragment IPv4 thật cho thấy fixed-IPID vẫn có thể bypass detector, trong khi flood được mitigated khi B5 trigger. Do đó B5 chưa được chứng minh an toàn hơn hoặc sẵn sàng triển khai.

## 9. Hạn chế và hướng tiếp theo

Các giới hạn chính vẫn còn tồn tại:

1. E1–E4 chủ yếu là controlled synthetic emulation; E5 chỉ dùng một phiên bản
   Unbound, một topology routed Docker và bốn workload.
2. E5 chưa phải deployment hoặc Internet evaluation; chưa có nhiều resolver,
   PCAP replay ngoài thực địa hay traffic DNS tự nhiên.
3. E5 có complete-block pairing theo workload nhưng chưa phải phép đo overhead
   đa resolver hoặc workload production; không dùng CPU flood để kết luận chi phí
   riêng của B5.
4. E2/E3 không có adaptive/high-entropy attacker trực tiếp và E3 chỉ kiểm tra
   60 candidate đã đăng ký.
5. Cỡ mẫu 20 run/case hoặc 20 pair/cell phù hợp để báo cáo CI trong phạm vi
   này, nhưng không bảo đảm phát hiện các event hiếm.

Hướng tiếp theo là mở rộng E5 với nhiều resolver, workload ghép cặp defense
off/on, PCAP replay hoặc traffic thực được kiểm soát, adaptive attacker đã
đăng ký trước và denominator rõ cho poisoning attempt/success.

## 10. Artifact để kiểm tra lại

- [E1 report](Report/experiments/E1/E1_report.md) và [validator](Report/experiments/E1/runs/E1_confirmatory_20260810_seed20260810_raw_v2/validation.json)
- [E2 report](Report/experiments/E2/E2_report.md) và [validator](Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/validation.json)
- [E3 report](Report/experiments/E3/E3_report.md) và [final validator](Report/experiments/E3/e3_validation.json)
- [E4 report](Report/experiments/E4/E4_report.md), [summary](Report/experiments/E4/e4_summary.json) và [final validator](Report/experiments/E4/e4_validation.json)
- [E5 report](Report/experiments/E5/E5_report.md)
- [E5 cách dựng lab](Report/experiments/E5/E5_LAB.md)
- [E5 protocol](Report/experiments/E5/e5_protocol.json)
- [E5 registration and image manifest](Report/experiments/E5/output/E5-routed-s20260902-r001/registered.json)
- [E5 aggregate confirmatory results](Report/experiments/E5/output/E5-routed-s20260902-r001/aggregate_confirmatory.json)
- [E5 per-run metrics](Report/experiments/E5/output/E5-routed-s20260902-r001/metrics_confirmatory.json)
- [E5 confirmatory validation PASS](Report/experiments/E5/output/E5-routed-s20260902-r001/validation_confirmatory.json)
- [E5 sanity validation PASS](Report/experiments/E5/output/E5-routed-s20260902-r001/validation_sanity.json)
- [E5 pilot validation PASS](Report/experiments/E5/output/E5-routed-s20260902-r001/validation_pilot.json)
