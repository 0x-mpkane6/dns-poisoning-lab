# E3 RE-ONBOARDING

## Tài liệu handover để tiếp tục đề tài POPS/Rℓ₂

**Mục đích của tài liệu:** đưa một thành viên đã rời project khoảng một tháng trở lại trạng thái có thể tiếp tục E3 mà không phải đoán protocol, tự chọn nhầm artifact hoặc dùng held-out test sai quy trình.

**Phạm vi hiện tại:** E3 chọn lại operating point cho detector Rℓ₂ cải tiến bằng dữ liệu quyết định của E2, sau đó đánh giá một lần trên held-out test. Các thí nghiệm hiện tại là controlled synthetic emulation. Chưa được suy ra kết quả triển khai thực tế, poisoning success, ASR, latency hay resource overhead.

**Nguồn ưu tiên khi có mâu thuẫn:**

1. Source snapshot và dữ liệu của canonical artifact E2.
2. `e2_protocol.json`, `validation.json` và `ARTIFACT_STATUS.md` của canonical E2.
3. Experiment plan đã khóa trong `refine-logs`.
4. E2/E1 report.
5. Outline `.docx` là định hướng E3; phần nào outline chưa quy định chi tiết phải được khóa trong E3 protocol trước khi chạy.

Nếu tài liệu/code không xác định được một chi tiết, dùng đúng nhãn **CHƯA XÁC ĐỊNH – CẦN KIỂM TRA**, không tự biến giả định thành protocol.

---

## 1. Tổng quan đề tài

Đề tài đánh giá và cải tiến cơ chế phát hiện DNS Cache Poisoning dựa trên POPS, với nhánh Rℓ₂ sử dụng thông tin về các fragment DNS. Ý tưởng gốc là khi resolver nhận dấu hiệu phản hồi DNS bị phân mảnh, nó kích hoạt bước bảo vệ. Cách làm này có thể bảo thủ: fragment hợp lệ cũng làm detector bật xử lý.

Phiên bản cải tiến bổ sung các đặc trưng của FRAG2 trong một cửa sổ thời gian:

- `samples` (`n`): số FRAG2 quan sát được trong cửa sổ;
- `entropy` (`H`): Shannon entropy của các giá trị IPID;
- `unique_ratio` (`U`): số IPID khác nhau chia cho tổng số IPID.

Operating point B5 hiện được đăng ký trong E2 là:

```text
FRAG2_WINDOW_SECONDS = 2.0
R2_MIN_SAMPLES = 24
R2_ENTROPY_THRESHOLD = 4.0
R2_UNIQUE_RATIO_THRESHOLD = 0.70
```

Detector trong source snapshot E2 xử lý theo thứ tự query-time:

1. FRAG2 có timestamp `<=` thời điểm query được đưa vào lịch sử.
2. Các event cũ hơn cửa sổ 2 giây bị loại theo semantics `timestamp < window_start`.
3. FRAG1 hiện tại chỉ được ghi nhận, không được đưa vào cửa sổ FRAG2.
4. Detector tính `samples`, `unique_ipids`, `entropy`, `unique_ratio`.
5. Mỗi policy B0-B5 được đánh giá trên cùng một cửa sổ.

`labs/r2entropy/resolver/resolver.py` là implementation detector dùng trong testbed. Hai primitive cần hiểu trước khi viết E3 là `shannon_entropy()` và `r2_should_block()`.

**Giới hạn quan trọng:** E2/E3 dùng event stream tổng hợp và resolver adapter, không phải IP fragmentation thật. Event “attack” trong E2 là synthetic stress regime, không phải bằng chứng một cuộc poisoning hoàn chỉnh.

---

## 2. B0-B5: logic và mục đích

Trong framework, detector policy được tách khỏi workload. Profile được biểu diễn bằng `R2_VARIANT` và trạng thái defense; topology không cần nhân bản.

| Profile | Logic | Mục đích |
|---|---|---|
| B0 — No defense | Luôn `allow`; `DEFENSE_MODE=off`. | Đối chứng không phòng vệ, dùng để hiểu baseline hệ thống. Trong E2 chủ yếu là detector reference; ASR thật không được suy ra từ E2. |
| B1 — POPS/Rℓ₂ original | Khi defense bật và gặp FRAG1 thì bật policy legacy, không xét feature. | Mốc so sánh trực tiếp với POPS/Rℓ₂ gốc; thể hiện chi phí/false trigger của policy bảo thủ. |
| B2 — Volume-only | `samples >= min_samples`. | Ablation để kiểm tra chỉ count/minimum volume đã đủ phân biệt chưa. Đây là baseline chính của E2/E3. |
| B3 — Entropy-only | `entropy >= entropy_threshold`. | Đo đóng góp riêng của entropy, không cho phép volume hoặc unique ratio quyết định. |
| B4 — Unique-only | `unique_ratio >= unique_ratio_threshold`. | Đo đóng góp riêng của độ đa dạng IPID. |
| B5 — Combined | `samples >= min_samples AND entropy >= threshold AND unique_ratio >= threshold`. | Cơ chế đề xuất ba biến; E2 cho thấy operating point cố định hiện tại chưa chứng minh được lợi ích so với B2. |

Trong code snapshot, B0 được biểu diễn là `no_defense`, B1 là `legacy`, B2 là `volume`, B3 là `entropy`, B4 là `unique`, B5 là `combined`. Các cờ tương ứng trong raw/CSV là:

```text
block_no_defense
block_legacy
block_volume
block_entropy
block_unique
block_combined
```

E3 cần tạo quyết định **B5 mới** offline từ ba cột feature và threshold candidate. Không được dùng `block_combined` của E2 như kết quả B5 mới, vì cờ đó chỉ phản ánh threshold cố định cũ `24/4.0/0.70`.

---

## 3. E1 đã làm gì?

### 3.1. Câu hỏi

E1 đo operating boundary của B5 trên benign traffic: khi tốc độ fragment hợp lệ tăng, detector bắt đầu bật bảo vệ nhầm từ đâu?

Trong E1, toàn bộ traffic là benign synthetic. Vì vậy “FPR” của E1 là tỷ lệ detector trigger trên lưu lượng hợp lệ, không phải tỷ lệ DNS answer sai.

### 3.2. Protocol

- Ba kiểu IPID/source behavior: `random2048`, `sequential`, `smallpool16`.
- Mức mục tiêu: `5, 12, 18, 24, 36, 60, 120, 300` fragment trong cửa sổ 2 giây.
- K = 20 run độc lập cho mỗi kiểu IPID và mỗi mức.
- 300 decision/run.
- 24 ô chính, 480 run, 144.000 quyết định; có thêm phần tải rất cao cho `random2048`.
- Không bật attacker.
- Cửa sổ và timing detector được giữ cố định.
- Các cửa sổ chồng lấn trong một run không được coi là IID; CI chính được gom theo run.

### 3.3. Kết quả chính

Với IPID ngẫu nhiên/tuần tự, FPR tăng mạnh quanh vùng 18-24 fragment/2 giây:

- mức 5: không ghi nhận trigger;
- mức 12: khoảng 0,07%-0,12%;
- mức 18: khoảng 10,0%-10,8%;
- mức 24: khoảng 50,1%-53,2%;
- mức 36: khoảng 97,6%-97,7%;
- mức 60-300: 100% trong dữ liệu đã chạy.

Với `smallpool16`, không ghi nhận trigger ở các mức vì entropy và/hoặc `unique_ratio` không đạt threshold. Đây vừa là giảm false trigger trên một pattern benign, vừa là failure probe tiềm tàng; E1 không có attacker nên chưa chứng minh được khả năng né.

### 3.4. Ý nghĩa cho E3

E1 cho thấy threshold B5 cũ có boundary rõ và `unique_ratio` ảnh hưởng mạnh đến behavior. E3 phải xem threshold mới có giảm trigger benign mà vẫn giữ alert trên synthetic attack hay không. E1 không được dùng để chọn threshold E3 nếu protocol E3 chỉ định chọn trên E2 validation; E1 dùng làm evidence/constraint bên ngoài, không được trộn tự do vào validation.

---

## 4. E2 đã làm gì và vì sao cần E2?

### 4.1. Khoảng trống trước E2

E2 được thực hiện vì các kết quả trước đó có ba vấn đề:

- benign và attack khác nhau về volume, nên không biết entropy/unique ratio có thêm giá trị độc lập hay chỉ phản ánh count;
- threshold `4.0/24/0.70` chưa được chọn và đánh giá bằng split tách biệt;
- chưa có protocol chặt về run độc lập, pairing, bootstrap, raw replay và uncertainty.

Task `benign-on` trước đó còn có artifact rỗng: `total_frag2_observed=0`, entropy bằng 0 do không có FRAG2 hợp lệ. `Report_task1.md` mô tả việc bổ sung FRAG2 benign, nhưng đó là vấn đề khác với câu hỏi volume-matched của E2.

### 4.2. Protocol E2 canonical

Canonical artifact là:

```text
research/Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/
```

Thiết kế:

- controlled synthetic emulation tại thời điểm query/FRAG1;
- mức volume: `24, 60, 120, 200` samples/window;
- continuous: Poisson với `lambda = level / 2s`;
- bursty: NHPP thinned square-wave, high/low `1.75lambda/0.25lambda`, nửa chu kỳ 1,5 s;
- 150 decision/run sau warm-up 6 s, query 4 Hz với phase được seed;
- benign và attack cùng profile/level/pair dùng chung exact FRAG2 timestamps và query timestamps;
- `max_abs_paired_samples_difference = 0` là điều kiện bắt buộc;
- attack condition có `benign_fraction=0.1`, thay origin/IPID nhưng giữ timestamp;
- seed namespace tách theo split/profile/level/pair/stream;
- independent unit là `pair_id`/paired trace, không phải 150 cửa sổ query.

Các condition:

```text
benign_continuous
attack_sweep_continuous
attack_random_continuous
attack_fixed_continuous
attack_dup_sweep_continuous
benign_bursty
attack_sweep_bursty
```

Vai trò condition:

- `attack_sweep_continuous` và `attack_sweep_bursty`: stress regime chính;
- `attack_random_continuous`: negative control;
- `attack_fixed_continuous` và `attack_dup_sweep_continuous`: failure probe độ đa dạng IPID thấp;
- benign condition tương ứng: reference để tính trigger/FPR.

### 4.3. Split canonical E2

Canonical E2 có ba split:

| Split | Quy mô canonical | Mục đích | Được dùng để chọn threshold? | Được dùng kết luận? |
|---|---:|---|---|---|
| `calibration` | 2 profile × 4 level × K=10 = 80 condition-run | Generator/occupancy QA và event-order QA. | Không. | Không. |
| `validation` | 7 condition × 4 level × K=10 = 280 condition-run | Khóa diagnostic scalar threshold E2. | Có, nhưng chỉ cho mục đích đã đăng ký. | Không. |
| `test` | 7 condition × 4 level × K=20 = 560 condition-run | Held-out confirmatory evidence. | Tuyệt đối không. | Có, một lần. |

Tổng canonical là 920 condition-run và 138.000 decisions. Con số tracker hiện hành `560 condition-runs / 84.000 decisions` là phần test confirmatory; toàn campaign gồm thêm 80 calibration và 280 validation. Có mâu thuẫn trong artifact: `e2_runs.csv` thực tế đếm được `calibration=80`, `validation=280`, `test=560`, phù hợp với `e2_protocol.json`, source `e2_confirmatory.py` và tracker; trong khi chi tiết check `disjoint_split_seed_namespaces` của `validation.json` ghi `calibration=160, test=320, validation=160`. Tuy vậy `validation.json` vẫn ghi `run_row_count observed=920`, `runs_replayed=920/920` và trạng thái tổng thể `PASS`. **CHƯA XÁC ĐỊNH – CẦN KIỂM TRA** nguyên nhân của detail count lệch này trong validator trước khi dùng E2 inventory làm bằng chứng mới. Khi triển khai E3, dùng `e2_runs.csv` + protocol/source để audit lại split counts và ghi cảnh báo này vào `e3_preflight.json`; không âm thầm bỏ qua.

### 4.4. Metric E2

Với mỗi pair:

```text
J = attack_alert_rate - benign_trigger_rate
Delta J = J(B5) - J(B2)
```

E2 báo thêm TPR/FNR/FPR synthetic, balanced precision ở class mix 50:50, PR-AUC/AUPRC feature-level và paired 95% CI bằng 5.000 whole-pair bootstrap resamples. Đây không phải ASR.

---

## 5. E2 đã chứng minh và chưa chứng minh gì?

### Đã chứng minh trong phạm vi E2

- E2 canonical là query-timed paired controlled emulation và validator độc lập PASS 18/18.
- Benign/attack volume được match chính xác theo từng paired query.
- Với threshold cũ `24/4.0/0.70`, B5 không vượt B2 trên sweep liên tục hoặc bursty: macro `Delta J` bằng 0 trong artifact, nằm trong biên tương đương đã đăng ký.
- B5 kém B2 trên fixed-IPID và duplicate-sweep synthetic failure probes.
- `unique_ratio` có tín hiệu xếp hạng tốt ở tải cao; trên sweep liên tục mức 200, AUPRC được báo là 0,992 và validation-locked scalar feature evaluation có FPR test 0,053 tại TPR test 0,980.
- Threshold scalar trong `e2_thresholds.json` được chọn từ validation và khóa trước test cho **diagnostic feature-level analysis**.

### Chưa chứng minh

- Chưa chứng minh B5 chống DNS cache poisoning tốt hơn, an toàn hơn hoặc giữ ASR tốt hơn B1.
- Chưa chứng minh synthetic attack alert là poisoning success/TPR tấn công thực tế.
- Chưa chứng minh IP fragmentation thật, Unbound/BIND, PCAP replay, TC→TCP đầy đủ hay triển khai production.
- Chưa chứng minh latency, throughput, CPU, memory hoặc deployment overhead.
- Chưa chứng minh threshold `24/4.0/0.70` là tối ưu; chính E2 nói nó chưa khai thác được tín hiệu unique ratio.
- Chưa chứng minh fixed/duplicate IPID là một kỹ thuật né detector thực tế; đó chỉ là detector-level synthetic probe.

E3 phải giữ nguyên ranh giới này.

---

## 6. E3 cần làm gì và trả lời câu hỏi nào?

### Câu hỏi E3

> Có operating point B5 nào trong grid đã đăng ký có thể cải thiện sự cân bằng giữa benign trigger và synthetic attack alert so với B5 cũ `24/4.0/0.70`, đồng thời có giữ được behavior cần thiết so với B2 và không làm xấu failure boundary quá mức, khi threshold được chọn chỉ từ validation và đánh giá một lần trên held-out test?

E3 không được bắt đầu bằng việc nhìn test để chọn điểm. E3 là threshold-selection experiment:

1. Dùng validation để chấm toàn bộ grid.
2. Chọn đúng một operating point theo criterion đã khóa trước.
3. Ghi threshold vào file immutable/locked.
4. Chỉ sau khi lock mới mở test.
5. Đánh giá B5 mới và so sánh với B2/B5 cũ trên test.

Nếu E3 chọn threshold bằng cách xem kết quả test, đó là protocol violation và toàn bộ test result không còn là held-out evidence.

---

## 7. Dữ liệu E3 lấy từ E2

### 7.1. Artifact đầu vào bắt buộc

Đường dẫn canonical:

```text
research/Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/
```

File dùng cho E3:

| File/path | Vai trò |
|---|---|
| `e2_protocol.json` | Protocol, split, seed derivation, conditions, levels, operating point cũ, raw schema và provenance. |
| `e2_preflight.json` | Kết quả calibration/occupancy QA; phải PASS, nhưng không dùng chọn threshold. |
| `validation.json` | Validator canonical PASS 18/18; phải đọc trước khi dùng data. |
| `e2_runs.csv` | Một dòng/run-condition; inventory, hash, run summary, block count/rate. |
| `e2_decisions.csv.gz` | Bảng decision-level thuận tiện cho grid scoring. |
| `raw_runs/` | Gzip JSONL theo split/condition/level/pair; dùng để replay và kiểm tra CSV. |
| `e2_results.json` | Kết quả E2 cũ, chỉ để hiểu baseline và đối chiếu, không thay thế việc tính E3. |
| `e2_summary.csv` | Bảng tổng hợp E2 cũ, không phải output E3. |
| `e2_thresholds.json` | Threshold scalar E2 cũ; đây là diagnostic feature-level, không phải grid E3 và không được ghi đè. |
| `artifact_manifest.json` | Hash/inventory canonical; E3 phải snapshot/hash đầu vào. |
| `source_snapshot/` | Code đúng phiên bản đã sinh artifact. |

### 7.2. Schema decision-level thực tế

Header của `e2_decisions.csv.gz` gồm:

```text
split
profile
condition
role
level
pair_id
schedule_seed
query_seed
payload_seed
arrival_schedule_sha256
query_schedule_sha256
query_idx
query_timestamp_seconds
window_start_seconds
frag1_ipid
samples
unique_ipids
entropy
unique_ratio
benign_events_in_window
attack_events_in_window
block_no_defense
block_legacy
block_combined
block_volume
block_entropy
block_unique
```

E3 cần tối thiểu các field:

- pairing/inventory: `split`, `profile`, `condition`, `role`, `level`, `pair_id`;
- reproducibility: `schedule_seed`, `query_seed`, `payload_seed`, hai schedule hash;
- decision identity: `query_idx`, `query_timestamp_seconds`, `window_start_seconds`;
- features: `samples`, `unique_ipids`, `entropy`, `unique_ratio`;
- label composition: `benign_events_in_window`, `attack_events_in_window`;
- comparison reference: các `block_*` hiện có.

Raw JSONL có record đầu tiên `record_type=run_meta`, tiếp theo là:

- `record_type=frag2`: `event_idx`, `timestamp_seconds`, `origin`, `ipid`;
- `record_type=decision`: các feature, timestamp và cờ block.

Raw meta xác nhận `schema_version=2`, `scheduled_queries=150`, `window_seconds=2.0`, hash schedule và câu query timing. E3 phải đọc raw để validate, không chỉ tin CSV.

### 7.3. Cách tính B5 mới

Với candidate `(H*, N*, U*)`:

```text
new_B5_block = (
    samples >= N*
    AND entropy >= H*
    AND unique_ratio >= U*
)
```

B5 cũ là:

```text
old_B5_block = block_combined
```

B2 cũ/mốc volume-only là:

```text
B2_block = block_volume
```

Không chạy lại `resolver.py` với threshold mới để tạo lại E2 raw; E3 offline scoring trên feature đã khóa là đủ cho câu hỏi threshold. Chỉ tích hợp threshold vào detector runtime sau khi E3 đã lock và báo cáo xong, hoặc khi protocol E3 ghi rõ cần một campaign runtime mới.

---

## 8. Split E3 và quy tắc tránh data leakage

### 8.1. Điều canonical E2 thực sự có

Canonical E2 chỉ có `calibration`, `validation`, `test`; không có split tên `train`. Outline E3 có câu “gợi ý 60% train/exploration, 20% validation, 20% held-out test”, nhưng đó là gợi ý thiết kế bổ sung, không phải split đã tồn tại trong canonical artifact.

Vì vậy:

- **Không gọi `calibration` là train.** Calibration chỉ có benign controls và protocol ghi rõ không fit rate/threshold.
- **Không tự chia lại test** thành train/validation; như vậy phá held-out test.
- **Không lấy E1, E2 report hoặc test metrics để chọn grid point.** Chúng chỉ làm context/constraint đã có trước.
- Nếu E3 bắt buộc phải dùng split 60/20/20 đúng nghĩa, phải tạo protocol/campaign E3 mới với seed namespace disjoint và không được dùng test canonical cũ như exploration. **CHƯA XÁC ĐỊNH – CẦN KIỂM TRA** là project muốn giữ split canonical E2 hay chạy campaign E3 mới.

### 8.2. Luồng đề xuất bám theo artifact canonical

Cho E3 offline trên artifact hiện có:

| Giai đoạn | Dữ liệu | Quyền sử dụng |
|---|---|---|
| Preflight | `calibration` + raw/replay | Chỉ kiểm tra inventory, event order, occupancy, pairing/schema. Không fit threshold. |
| Threshold selection | `validation` | Chấm 60 operating points, tính metric, chọn một điểm theo criterion đã khóa. Có thể xem toàn bộ validation grid. |
| Lock | Không đọc metric test | Ghi threshold, criterion, candidate ranking, protocol hash và thời điểm lock vào artifact immutable. |
| Final evaluation | `test` | Tính một lần B5 mới, B5 cũ, B2 và các baseline cần báo cáo. Không đổi threshold sau bước này. |

Tất cả window của một `pair_id` phải ở cùng partition. Khi pairing benign/attack, chỉ ghép cùng `profile`, `level`, `pair_id`, và phải kiểm tra hai schedule hash giống nhau. Không được ghép một run validation với một run test chỉ vì cùng `level`.

### 8.3. Leakage checklist

- Threshold candidate không được sinh từ test quantile.
- Không chọn theo test FPR/TPR/PR-AUC.
- Không xem heatmap test trước khi lock.
- Không retune sau khi thấy failure probe test.
- Không dùng các decision window trong cùng run như 150 mẫu IID; bootstrap theo pair/run.
- Không dùng `e2_thresholds.json` của E2 như “đã chọn xong” cho B5 mới.
- Không ghi đè artifact E2 canonical hoặc file threshold E2 cũ.
- Nếu cần sửa protocol sau khi xem validation, phải tạo protocol/campaign mới; không giữ test cũ để kết luận mới.

---

## 9. Grid threshold E3

Outline đã đăng ký grid:

```text
entropy_threshold ∈ {2, 3, 4, 5, 6}        # 5 giá trị
min_samples       ∈ {8, 16, 24, 48}         # 4 giá trị
unique_ratio      ∈ {0.5, 0.7, 0.9}         # 3 giá trị
```

Tổng số operating points:

```text
5 × 4 × 3 = 60 operating points
```

Mỗi operating point cần được chấm trên toàn bộ validation cells đã đăng ký, không chỉ trên một condition đẹp. Tối thiểu phải bao gồm:

- hai primary stress regime: `attack_sweep_continuous`, `attack_sweep_bursty`;
- `attack_random_continuous` negative control;
- `attack_fixed_continuous` và `attack_dup_sweep_continuous` failure probes;
- benign control tương ứng theo profile;
- cả bốn level `24, 60, 120, 200`.

**CHƯA XÁC ĐỊNH – CẦN KIỂM TRA:** outline chưa nói rõ E3 có được mở rộng thêm grid khác, thêm condition adaptive/high-entropy hay không. Không tự mở rộng grid trong campaign xác nhận đầu tiên.

---

## 10. Cách chọn threshold trên validation

### 10.1. Điều đã được quy định

Outline quy định:

- chỉ validation được dùng để chọn operating point;
- phải đánh giá held-out test sau khi lock;
- E3 phải kiểm tra operating point mới so với B2/B5 cũ;
- E2 đã đăng ký `J`/`Delta J`, paired CI và biên thực tiễn `±0,05`.

### 10.2. Điều chưa được quy định đủ

**CHƯA XÁC ĐỊNH – CẦN KIỂM TRA:** outline không khóa một công thức duy nhất để xếp hạng 60 candidate và không khóa tie-breaking cho trường hợp nhiều candidate cùng đạt metric. Vì vậy không được tự viết “threshold tối ưu” rồi mới ghi protocol sau khi thấy kết quả.

Trước khi chạy validation, phải thêm vào `e3_protocol.json`:

1. metric chính dùng để chọn;
2. constraint tối thiểu trên attack alert/TPR;
3. trọng số giữa primary sweep liên tục và bursty;
4. cách xử lý failure probe;
5. tie-breaking deterministic;
6. cách xử lý candidate không đạt constraint;
7. candidate cũ `24/4.0/0.70` có được xem như control trong grid hay chỉ là comparator ngoài grid.

### 10.3. Criterion cần khóa trước khi code

Một lựa chọn phù hợp với mục tiêu outline là **maximize validation separation**:

```text
J = attack_alert_rate - benign_trigger_rate
```

với `attack_alert_rate` là tỷ lệ block trên synthetic attack và `benign_trigger_rate` là tỷ lệ block trên benign. Khi có nhiều attack condition, không nên chỉ tối ưu một condition mà phải khóa macro aggregation, ví dụ macro-average theo các primary condition và level. Cách chính xác vẫn là quyết định của chủ project trước khi code.

Một protocol candidate có thể ghi rõ như sau, nhưng phải được xác nhận/đăng ký trước khi chạy:

```text
Primary objective:
  maximize macro validation DeltaJ(new_B5 - B2)
  hoặc maximize macro validation J(new_B5), theo framing đã chọn.

Constraints:
  attack alert/TPR tối thiểu trên primary sweep;
  không được làm failure probes xấu hơn giới hạn đã đăng ký;
  benign trigger/FPR phải được báo cáo, không che khuất bằng aggregate.

Comparators:
  B2 = volume-only cũ;
  old B5 = 24/4.0/0.70;
  B1/B3/B4 dùng làm ablation context.
```

Đây là **đề xuất cần khóa**, không phải criterion hiện hành đã được project đăng ký. E2 chỉ có criterion cho paired effect và scalar diagnostic threshold: “largest empirical threshold with attack alert rate >= 0.95”. Không được nhầm criterion scalar E2 với criterion chọn 3D grid E3.

### 10.4. Tie-breaking cần deterministic

Nếu protocol chọn candidate theo một score chính, tie-breaking phải được ghi trước. Thứ tự bảo thủ có thể xem xét là:

1. score chính cao hơn;
2. benign trigger/FPR thấp hơn;
3. giữ attack alert/TPR cao hơn;
4. ưu tiên candidate gần old B5 để giảm thay đổi;
5. thứ tự từ điển cố định `(min_samples, entropy, unique_ratio)`.

Nhưng thứ tự trên chỉ là mẫu triển khai. **CHƯA XÁC ĐỊNH – CẦN KIỂM TRA** nếu chưa được project phê duyệt. Không tie-break bằng test metric.

### 10.5. Cách chấm validation

Với mỗi candidate và mỗi validation pair:

1. Tính `new_B5_block` từ `samples`, `entropy`, `unique_ratio`.
2. Ghép với benign cùng profile/level/pair.
3. Tính attack alert rate, benign trigger rate và `J` cho từng pair.
4. Tổng hợp theo pair, không coi query là đơn vị độc lập.
5. Tính macro theo level/condition theo aggregation đã đăng ký.
6. Tính paired CI/bootstrap nếu criterion dùng CI.
7. Lưu **tất cả 60 candidate**, không chỉ lưu candidate thắng.

Không được tính “TPR/FPR” bằng cách giả định event `origin=attack` trong cửa sổ là một poisoning success. Trong E2, đây là synthetic detector label.

---

## 11. Lock threshold và held-out test

### 11.1. Lock

Sau khi validation scoring hoàn tất và criterion/tie-break đã được áp dụng:

- ghi đúng một candidate vào `e3_locked_threshold.json`;
- ghi toàn bộ grid ranking vào `e3_validation_grid.csv`/JSON;
- ghi `selected_candidate`, criterion version, constraints, tie-break, validation artifact hash, input manifest hash, source commit/hash và timestamp;
- đặt `status: locked-before-test`;
- làm file immutable về mặt workflow: không sửa nội dung sau khi test bắt đầu;
- tạo hash của lock file và ghi vào metadata test.

Không được lock chỉ bằng một biến môi trường không được lưu lại. Không được ghi đè `e2_thresholds.json`.

### 11.2. Test

Chỉ mở test sau khi:

1. preflight canonical PASS;
2. validation grid đủ 60 candidate;
3. criterion và tie-break có trong protocol trước lock;
4. `e3_locked_threshold.json` đã ghi/hash;
5. validator kiểm tra test chưa bị đọc trong selection path;
6. test inventory/schedule/hash disjoint được xác nhận.

Trên test, dùng đúng candidate đã lock để tính một lần:

- B5 mới;
- B5 cũ `block_combined`;
- B2 `block_volume`;
- B1/B3/B4 nếu bảng final yêu cầu;
- primary/failure/negative-control condition;
- cả bốn level.

Không thay threshold nếu test cho kết quả xấu. Nếu cần threshold khác, đó là E3 campaign mới: phải tạo protocol mới và giữ test cũ là evidence của candidate cũ, không cherry-pick.

---

## 12. Metric và cách so sánh B5 mới

### 12.1. Metric detector bắt buộc

Theo outline và pattern E2, nên báo:

- `attack_alert_rate` / synthetic TPR;
- `benign_trigger_rate` / synthetic FPR;
- FNR `= 1 - attack_alert_rate`;
- precision balanced 50:50, ghi rõ đây không phải deployment prevalence;
- `J = attack_alert_rate - benign_trigger_rate`;
- `Delta J(new_B5 - B2)`;
- `Delta J(new_B5 - old_B5)`;
- `Delta J(new_B5 - B1)`, nếu giữ bảng paired ablation;
- PR-AUC/AUPRC của từng score và score/threshold mới khi phù hợp;
- 95% CI theo pair/run, 90% CI nếu verdict practical equivalence dùng biên E2.

### 12.2. Metric feature-level

Giữ riêng:

- phân phối `samples`, `entropy`, `unique_ratio` theo condition/level;
- AUPRC từng feature với chiều `higher_is_suspicious` đã khóa;
- validation-only heatmap/grid score;
- test-only performance của candidate lock.

Không gọi AUPRC của feature là bằng chứng B5 combined tốt hơn B2.

### 12.3. So sánh cần có

Bảng final tối thiểu:

| So sánh | Ý nghĩa |
|---|---|
| B5 mới vs B2 | Câu hỏi chính: threshold mới có thêm separation so với count-only không? |
| B5 mới vs B5 cũ | Threshold tuning có cải thiện operating point hiện hành không? |
| B5 mới vs B1 | Còn khác baseline POPS/Rℓ₂ gốc ở detector decision không? |
| B5 mới vs B3/B4 | Thành phần entropy/unique và interaction có thay đổi không? |
| B5 mới trên fixed/duplicate | Có bảo toàn hay làm xấu failure boundary synthetic không? |

Primary effect nên ghi rõ:

```text
DeltaJ_new_vs_B2 = J(new_B5) - J(B2)
DeltaJ_new_vs_old = J(new_B5) - J(old_B5)
```

Nếu dùng macro qua bốn level, tạo macro value theo pair trước rồi bootstrap 5.000 pair, giống cấu trúc E2. Không bootstrap trực tiếp 150 query như IID.

### 12.4. Metric hệ thống

Outline liệt kê ASR, latency p50/p95/p99, throughput, CPU, memory. Artifact E2 hiện không hỗ trợ các metric này theo nghĩa end-to-end. E3 offline không được tự điền chúng bằng detector alert rate. Nếu không chạy runtime campaign, ghi `CHƯA ĐO – CẦN E5/runtime validation`.

---

## 13. Output/artifact E3 cần tạo

Tạo thư mục mới, không ghi vào canonical E2:

```text
research/Report/experiments/E3/runs/E3_threshold_grid_<date>_<id>/
```

Cấu trúc đề xuất:

```text
E3_threshold_grid_<id>/
├── e3_protocol.json
├── e3_input_manifest.json
├── e3_preflight.json
├── e3_validation_grid.csv
├── e3_validation_grid.json
├── e3_locked_threshold.json
├── e3_test_results.csv
├── e3_test_results.json
├── e3_summary.csv
├── e3_decisions.csv.gz              # nếu lưu lại decision-level derived flags
├── e3_validation_scores/            # tùy chọn, per pair/cell
├── figures/
│   ├── validation_heatmap_*.png
│   ├── pareto_operating_points_*.png
│   ├── test_comparison_*.png
│   └── failure_boundary_*.png
├── source_snapshot/
│   ├── e3_select.py
│   ├── e3_validate.py
│   ├── e3_report.py
│   └── e3_plot.py
├── validation.json
├── artifact_manifest.json
├── E3_report.md
└── notes.txt
```

Tên file có thể thay đổi, nhưng artifact phải có đủ nội dung sau:

- protocol trước khi chạy;
- input artifact path/hash và source snapshot/hash;
- inventory split/run/pair;
- đầy đủ 60 operating points và metric validation;
- candidate đã lock cùng criterion/tie-break;
- test result chỉ sau lock;
- raw-to-derived validator;
- figures từ validation và test nhưng phân biệt nguồn rõ ràng;
- report nói rõ scope controlled emulation;
- manifest SHA-256.

---

## 14. File/code phải đọc trước khi bắt đầu code

### Bắt buộc đọc

1. `Outline_thuc_nghiem_bo_sung_dieu_chinh.docx` — yêu cầu E3, grid và định hướng split.
2. `refine-logs/EXPERIMENT_PLAN_20260813_163156.md` — protocol E2 đã khóa và các claim gate.
3. `refine-logs/EXPERIMENT_TRACKER_20260813_163156.md` — trạng thái các mốc E2.
4. `research/Report/experiments/E2/ARTIFACT_STATUS.md` — canonical/historical/provisional boundary.
5. `research/Report/experiments/E2/E2_report.md` — kết quả và cách diễn giải.
6. `research/Report/experiments/E1/E1_report.md` — operating boundary và failure behavior benign.
7. `research/Report/framework/README.md` — B0-B5, topology và artifact convention.
8. `labs/r2entropy/resolver/resolver.py` — detector runtime và semantics window.

### Canonical E2 cần đọc trực tiếp

1. `research/Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/e2_protocol.json`
2. `.../validation.json`
3. `.../e2_preflight.json`
4. `.../e2_runs.csv`
5. `.../e2_decisions.csv.gz`
6. `.../raw_runs/`
7. `.../e2_results.json`
8. `.../e2_thresholds.json`
9. `.../artifact_manifest.json`

### Script/source snapshot cần đọc

1. `.../source_snapshot/e2_confirmatory.py` — schedule, raw schema, split execution, E2 threshold scalar selection và aggregate.
2. `.../source_snapshot/e2_validate.py` — raw replay, pair/hash check, threshold/test validation.
3. `.../source_snapshot/e2_report.py` — cách report E2 và thuật ngữ.
4. `.../source_snapshot/e2_plot_confirmatory.py` — figure conventions.
5. `.../source_snapshot/resolver.py` — exact detector primitives đã dùng.
6. `research/Report/experiments/E2/e2_confirmatory.py`, `e2_validate.py`, `e2_report.py` — source working tree; so sánh hash với snapshot trước khi reuse.

**Cảnh báo provenance:** canonical protocol ghi `git_provenance.dirty=true` và có source files modified/untracked tại thời điểm chạy. Vì vậy source working tree hiện tại không mặc nhiên là source đã sinh canonical. Khi viết E3, phải hash/snapshot code E3 và giữ canonical E2 input bất biến.

---

## 15. File/code có khả năng cần tạo hoặc sửa

### Nên tạo mới

- `research/Report/experiments/E3/e3_select.py`: đọc E2 decision data, tính 60 candidate trên validation, ghi grid và chọn candidate theo protocol.
- `research/Report/experiments/E3/e3_validate.py`: kiểm tra input inventory, leakage, split, feature replay, lock-before-test và test aggregate.
- `research/Report/experiments/E3/e3_report.py`: sinh report sau khi validation/test PASS.
- `research/Report/experiments/E3/e3_plot.py`: heatmap, Pareto/operating-point, comparison và failure boundary.
- `research/Report/experiments/E3/README.md`: hướng dẫn chạy/reproduce E3.
- `research/Report/experiments/E3/runs/.../e3_protocol.json`: protocol đăng ký trước mỗi campaign.

### Có thể cần sửa sau khi protocol được khóa

- `labs/r2entropy/resolver/resolver.py` hoặc profile config nếu muốn tích hợp threshold E3 vào runtime.
- `research/Report/framework/config/b5.env` nếu threshold cuối cùng phải trở thành profile B5 mới.
- `research/Report/framework/run.sh` chỉ nếu E3 cần một campaign runtime mới; không sửa chỉ để làm offline replay.

Không nên sửa E2 script để “tận dụng” output. Hãy giữ E2 canonical và tạo E3 code path riêng. Nếu phải dùng helper chung, copy/snapshot có hash hoặc import rõ version, không âm thầm thay đổi semantics E2.

---

## 16. Execution plan từng bước

### Bước 0 — Xác nhận trạng thái repository

1. Kiểm tra git status và các thay đổi người dùng hiện có.
2. Không revert thay đổi ngoài task.
3. Kiểm tra `ARTIFACT_STATUS.md` và xác nhận canonical path.
4. Ghi commit/source hash của canonical E2 và hash các input files.

**Output:** `e3_input_manifest.json` bản nháp; chưa chạy threshold.

### Bước 1 — Preflight canonical E2

1. Kiểm tra file bắt buộc tồn tại.
2. Đọc `validation.json`, yêu cầu `status=PASS`.
3. Đọc `e2_protocol.json`, xác nhận raw schema 2, query 150, window 2s, four levels, conditions và split.
4. Đọc `e2_runs.csv`, kiểm tra key `(split, condition, level, pair_id)` duy nhất.
5. Kiểm tra số run theo split và condition.
6. Kiểm tra mọi raw file tồn tại, SHA khớp `e2_runs.csv`.
7. Replay raw hoặc gọi validator E2 để xác nhận feature CSV khớp raw.
8. Kiểm tra schedule hash và occupancy pair trên validation/test.

**Không đạt:** dừng; không tính grid. Sửa input/protocol hoặc tạo campaign mới, không “bỏ qua vài dòng lỗi”.

### Bước 2 — Viết và đăng ký E3 protocol

1. Ghi rõ E3 offline replay hay E3 runtime re-run.
2. Ghi input canonical path/hash.
3. Ghi 60-point grid.
4. Ghi split chính thức: calibration chỉ QA, validation chọn, test held-out.
5. Ghi primary metric, constraints, macro aggregation và tie-breaking.
6. Ghi old B5/B2 comparator.
7. Ghi bootstrap seed/replicate và independent unit.
8. Ghi điều kiện lock-before-test.
9. Ghi output schema và artifact path mới.
10. Chụp source snapshot/provenance trước khi chạy.

Nếu criterion/tie-break chưa được quyết định, để `CHƯA XÁC ĐỊNH – CẦN KIỂM TRA` trong handover nhưng **không chạy campaign xác nhận**.

### Bước 3 — Implement offline scoring

1. Đọc `e2_decisions.csv.gz` bằng streaming gzip CSV.
2. Giữ các khóa và hash; không bỏ `pair_id`.
3. Với mỗi 60 candidate, tính cờ B5 mới từ ba feature.
4. Tính metric validation theo pair.
5. Tính B2 và old B5 từ cờ gốc để comparator.
6. Tạo grid table đủ 60 rows/candidate, có condition/level/profile breakdown.
7. Không đọc test trong code selection; nếu cùng process đọc test, phải tách module/phase và validator audit rõ.

### Bước 4 — Validate validation grid

1. Kiểm tra candidate count = 60.
2. Kiểm tra mọi validation cell đều có đủ pair.
3. Kiểm tra pairing schedule hash.
4. Kiểm tra candidate scores tái tính được từ feature input.
5. Kiểm tra không có test row trong selection input.
6. Kiểm tra metric/CI dùng pair-level unit.
7. Kiểm tra selected candidate và tie-break tái lập được từ protocol.

### Bước 5 — Chọn và lock

1. Chạy selection đúng một lần trên validation.
2. Lưu toàn bộ ranking và lý do loại candidate.
3. Chọn candidate theo criterion đã đăng ký.
4. Ghi `e3_locked_threshold.json` và hash.
5. Chạy validator lock-before-test.
6. Từ thời điểm này không sửa candidate, grid criterion hoặc input manifest.

### Bước 6 — Held-out test

1. Mở test chỉ khi lock PASS.
2. Tính B5 mới một lần trên test.
3. Tính old B5 và B2 từ cùng test rows.
4. Tính các baseline B1/B3/B4 và failure probes.
5. Bootstrap theo pair/run, 5.000 replicates nếu giữ E2 convention.
6. Ghi test results; không đẩy kết quả quay lại selection.

### Bước 7 — Figures/report

1. Heatmap validation của 60 point, đánh dấu old B5 và selected point.
2. Pareto/operating-point plot theo criterion.
3. Test comparison B5 mới/B5 cũ/B2.
4. Failure boundary fixed/duplicate và negative control.
5. Bảng metric/CI.
6. Report ghi rõ candidate được chọn trên validation và test chỉ dùng sau lock.

### Bước 8 — Integrity và promote

1. Chạy E3 validator độc lập.
2. Hash toàn bộ output.
3. Kiểm tra report chỉ đọc test result sau lock.
4. Kiểm tra không overwrite artifact E2.
5. Chỉ gọi artifact là canonical E3 khi validator PASS và protocol/report cùng hash/provenance.

---

## 17. Checklist trước khi chạy E3

### Input và provenance

- [ ] Đúng canonical path `E2_confirmatory_20260814_complete_b0_ablation`.
- [ ] `ARTIFACT_STATUS.md` xác nhận đây là canonical.
- [ ] `validation.json` là `PASS` 18/18.
- [ ] `artifact_manifest.json` và SHA input đã lưu.
- [ ] Không dùng provisional, smoke hoặc superseded artifact.
- [ ] Source snapshot E2 đã được đọc và hash.

### Protocol

- [ ] Protocol E3 được ghi trước selection.
- [ ] Grid có đúng 60 operating points.
- [ ] Calibration không được dùng fit threshold.
- [ ] Validation là selection split.
- [ ] Test là held-out, chưa được đọc để chọn.
- [ ] Primary metric, constraint, aggregation và tie-break đã khóa.
- [ ] Old B5 `24/4.0/0.70` và B2 được định nghĩa comparator.
- [ ] Independent unit là pair/run, không phải query.
- [ ] Bootstrap seed/replicate đã ghi.

### Code

- [ ] B5 mới được tính từ feature columns, không dùng lại `block_combined`.
- [ ] B2 comparator dùng `block_volume` hoặc recompute đúng semantics.
- [ ] Không thay đổi E2 resolver/source snapshot.
- [ ] Output path mới, không overwrite.
- [ ] Có raw/CSV replay validation.
- [ ] Có kiểm tra lock-before-test.

### Test gate

- [ ] Tất cả 60 validation candidate đã có score.
- [ ] Candidate được lock và hash trước test.
- [ ] Không còn chỉnh threshold sau lock.
- [ ] Test chỉ chạy một lần theo candidate đã lock.
- [ ] Report phân biệt synthetic alert với ASR/poisoning.

---

## 18. Lỗi/protocol violation cần tránh

1. Dùng `e2_thresholds.json` của E2 như threshold E3. File đó chỉ chứa scalar diagnostic threshold theo condition/level/feature, không phải 3D grid B5.
2. Dùng `test` để chọn candidate vì test FPR đẹp hơn.
3. Chia nhỏ các query window chồng lấn thành IID observations.
4. Gộp benign và attack khác `pair_id` nhưng vẫn gọi là paired.
5. Không kiểm tra schedule hash/occupancy exact match.
6. Gọi `attack_alert_rate` là TPR poisoning hoặc ASR.
7. Gọi fixed/duplicate probe là attack success hoặc detector bypass ngoài đời.
8. Tự thêm adaptive/high-entropy condition vào campaign mà không re-register protocol.
9. Tự đổi grid, thêm threshold hoặc bỏ candidate sau khi nhìn validation.
10. Dùng test để chỉnh criterion/tie-break.
11. Ghi đè canonical E2, `e2_thresholds.json`, `e2_results.json` hoặc raw.
12. Trộn calibration vào validation vì calibration có occupancy đẹp.
13. Báo FPR=0 như xác suất thật bằng 0 mà không có CI/exact interval.
14. Report chỉ trung bình, bỏ qua run variability hoặc failure probe.
15. Dùng source working tree khác source snapshot nhưng không ghi provenance.
16. Tích hợp threshold vào runtime trước khi offline E3 lock.
17. Đếm `unique_ratio` khi `samples=0` mà không giữ semantics hiện tại (`0.0`).
18. Nhầm `unique_ipids` là số unique tuyệt đối của toàn campaign; đây là unique count trong từng decision window.

---

## 19. Các outcome có thể xảy ra sau E3

### Outcome A — B5 mới cải thiện rõ so với B2

Điều kiện cần theo framing E2: CI 95% của `Delta J(new_B5 - B2)` vượt cổng meaningful đã đăng ký, và không có failure boundary unacceptable theo constraint.

Bước tiếp theo:

- giữ threshold đã lock;
- báo cáo effect size/CI và tất cả negative result;
- chạy E4 reporting/statistical synthesis;
- sau đó ưu tiên E5/runtime validation với resolver/IP fragmentation thật;
- không gọi production-ready chỉ từ E3.

### Outcome B — B5 mới tương đương B2

Điều kiện: CI theo quy tắc practical equivalence nằm trong biên đã đăng ký, hoặc không có evidence vượt B2.

Bước tiếp theo:

- báo cáo negative/neutral result trung thực;
- framing contribution sang threshold/operating boundary hoặc volume-based detection nếu phù hợp;
- không tuyên bố entropy/unique tạo lợi ích độc lập;
- cân nhắc E3 mở rộng chỉ khi có hypothesis mới và protocol mới.

### Outcome C — B5 mới kém B2

Điều kiện: Delta J âm qua cổng degradation hoặc failure probes xấu hơn.

Bước tiếp theo:

- giữ failure boundary trong report;
- không bỏ candidate xấu khỏi report;
- xem xét sửa detector/logic AND, ngưỡng thấp/quá cao hoặc framing;
- tạo E3/E4 protocol mới nếu đổi cơ chế; không retune trên cùng held-out test.

### Outcome D — Không kết luận được

Nguyên nhân có thể là CI rộng, run variability cao, thiếu pair hoặc validator không đủ.

Bước tiếp theo:

- báo inconclusive, không chọn run đẹp;
- kiểm tra power/K và dữ liệu nhưng không tăng K tùy tiện sau khi nhìn kết quả;
- nếu cần K mới, đăng ký campaign mới với seed namespace mới;
- không dùng test cũ vừa xem để làm validation mới.

### Outcome E — Protocol/data failure

Ví dụ: raw replay fail, schedule hash lệch, candidate count thiếu, lock sau test, manifest mismatch.

Bước tiếp theo:

- dừng promotion;
- sửa code/protocol ở artifact mới;
- chạy lại campaign cần thiết;
- đánh dấu artifact lỗi/provisional, không dùng làm confirmatory evidence.

---

## 20. TÔI CẦN LÀM GÌ NGAY BÂY GIỜ?

Thứ tự công việc cụ thể:

1. Mở và đọc lại `Outline_thuc_nghiem_bo_sung_dieu_chinh.docx`, `refine-logs/EXPERIMENT_PLAN_20260813_163156.md`, `research/Report/experiments/E2/ARTIFACT_STATUS.md` và `E2_report.md`.
2. Xác nhận canonical artifact tại `research/Report/experiments/E2/runs/E2_confirmatory_20260814_complete_b0_ablation/`; không dùng `smoke`, `provisional` hoặc artifact đã superseded.
3. Đọc `e2_protocol.json`, `validation.json`, `e2_preflight.json`, `e2_runs.csv`, header của `e2_decisions.csv.gz` và một raw JSONL gzip.
4. Chạy/kiểm tra E2 validator để chắc chắn canonical input vẫn PASS; nếu fail thì dừng E3.
5. So sánh hash/source snapshot của E2 với working tree; ghi nhận canonical provenance dirty và không sửa artifact E2.
6. Quyết định và ghi vào E3 protocol phần hiện còn thiếu: metric chính, constraint, macro aggregation, treatment failure probes, old B5 comparator và tie-breaking.
7. Chốt split E3: dùng calibration chỉ preflight, validation để chọn, test held-out để đánh giá; không tự gọi calibration là train 60%.
8. Tạo thư mục `research/Report/experiments/E3/` và một run output mới, không tạo file trong canonical E2.
9. Viết `e3_select.py` để score đúng 60 operating points từ feature columns; lưu toàn bộ validation grid và comparator B2/B5 cũ.
10. Viết `e3_validate.py` để kiểm tra pair/hash/schema/leakage/candidate count và tái tính validation scores.
11. Chạy preflight và validation selection; chưa đọc/aggregate held-out test cho tới khi lock validator PASS.
12. Ghi `e3_locked_threshold.json` với criterion, tie-break, input hash, source hash và `status=locked-before-test`.
13. Chạy test đúng một lần bằng threshold đã lock; tính B5 mới, B5 cũ, B2 và failure probes với paired run-level CI.
14. Sinh figures, report, manifest và chạy validator cuối. Chỉ sau PASS mới gọi artifact là canonical E3.
15. Nếu E3 không vượt B2 hoặc có failure boundary, báo cáo đúng kết quả và quyết định bước tiếp theo theo mục Outcome; không retune trên test cũ.

**Điểm cần giải quyết trước mọi dòng code E3:** criterion chọn 60 candidate và tie-breaking hiện chưa được outline khóa đầy đủ. Đây là blocker phương pháp luận, không phải chi tiết có thể tùy ý quyết định sau khi xem validation/test.
