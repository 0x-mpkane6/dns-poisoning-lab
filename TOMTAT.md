# Tóm tắt thư mục `refine-logs` và `research`

## 1. Phạm vi tổng quan

Hai thư mục này phục vụ hai lớp công việc khác nhau trong dự án DNS cache poisoning:

- `refine-logs`: nhật ký lập kế hoạch, kiểm soát tiến độ và khóa giao thức cho các chiến dịch thí nghiệm.
- `research`: mã nguồn framework, mã chạy thí nghiệm, dữ liệu artifact, báo cáo và bằng chứng dùng để phân tích các detector B0-B5.

Quan hệ tổng quát:

```text
refine-logs
    -> định nghĩa câu hỏi, claim, protocol, ma trận chạy và cổng kiểm tra
research/Report/framework
    -> framework Docker dùng chung để chạy testbed
research/Report/experiments/E1, E2
    -> mã thí nghiệm, các lần chạy và artifact
research/Report/experiments/E1/E1_report.md
research/Report/experiments/E2/E2_report.md
research/Report/Report_task1.md
    -> kết quả và diễn giải nghiên cứu
```

## 2. Thư mục `refine-logs`

### Nhiệm vụ

`refine-logs` là nơi ghi lại quá trình thiết kế và tinh chỉnh thí nghiệm. Các file ở đây không phải mã chạy hay dữ liệu đo trực tiếp; chúng là hồ sơ phương pháp, dùng để:

- nêu câu hỏi nghiên cứu và các claim được phép kết luận;
- cố định ngưỡng, mức tải, số lần chạy, seed và cách chia calibration/validation/test;
- theo dõi các mốc chạy từ kiểm tra sanity đến báo cáo;
- bảo đảm kết quả không bị retune, ghi đè hoặc diễn giải vượt quá phạm vi bằng chứng.

### Các file

#### `EXPERIMENT_PLAN.md`

Đây là file chỉ dẫn ngắn và là điểm vào của kế hoạch hiện hành. File xác nhận bản đang dùng là `EXPERIMENT_PLAN_20260813_163156.md`. Nó ghi rõ thiết kế E2 hiện tại không dùng rate calibration trên dữ liệu báo cáo; mỗi cặp benign/attack dùng chung FRAG2 và query timestamp trace nên occupancy khớp theo từng query. Chỉ K=20 test được dùng làm kết quả.

#### `EXPERIMENT_PLAN_20260813_160637.md`

Đây là bản kế hoạch E2 trước khi khóa. Nội dung mô tả:

- mục tiêu kiểm tra entropy và `unique_ratio` có thêm khả năng phân biệt so với volume-only hay không;
- claim map C1/C2 và các kết luận bị cấm như ASR, poisoning, latency, CPU hoặc triển khai thực tế;
- bốn block chính: kiểm tra thứ tự FRAG2/FRAG1, calibration, held-out evaluation và failure boundary;
- các profile IPID, mức volume, metric, tiêu chí pass/fail, rủi ro và ngân sách chạy.

Bản này có tính chất lịch sử/thiết kế ban đầu. Tracker tương ứng vẫn ở trạng thái TODO.

#### `EXPERIMENT_PLAN_20260813_163156.md`

Đây là kế hoạch E2 đã khóa và là bản chuẩn cần tham chiếu. Những điểm quan trọng:

- B5 dùng đồng thời `samples >= 24`, `entropy >= 4,0`, `unique_ratio >= 0,70` trong cửa sổ 2 giây;
- mức tải là 24, 60, 120 và 200 mẫu/cửa sổ;
- có 7 điều kiện synthetic: benign liên tục, attack sweep/random/fixed/duplicate liên tục và benign/attack bursty;
- benign và attack trong cùng cặp dùng chung lịch FRAG2 và lịch query;
- calibration, validation và test dùng namespace seed độc lập;
- test held-out K=20 là nguồn kết quả duy nhất;
- tiêu chí claim chính là khoảng tin cậy bootstrap 95% của `Delta J = J(B5) - J(B2)` phải có cận dưới lớn hơn `+0,05` mới được nói B5 có lợi ích đáng kể.

Phần `Must-run blocks` và `Cổng promotion` mô tả các điều kiện bắt buộc trước khi viết báo cáo: replay raw, khớp số mẫu theo cặp, validator độc lập, provenance/hash và không dùng dữ liệu validation để kết luận.

#### `EXPERIMENT_TRACKER.md`

Tracker bản đầu, đi cùng kế hoạch chưa khóa. Nó liệt kê các mốc E2-R001 đến E2-R005 nhưng tất cả còn `TODO`. Đây là ảnh chụp tiến độ ban đầu, không phản ánh trạng thái hoàn tất hiện tại.

#### `EXPERIMENT_TRACKER_20260813_160637.md`

Tracker của kế hoạch ban đầu. Các mốc gồm sanity, freeze rate scale, volume matching, confirmatory run và validator/report. Ma trận lúc này dự kiến 480 run và 144.000 quyết định cho phần chính. Tất cả đang ở `TODO` vì file được tạo trước khi chạy chiến dịch.

#### `EXPERIMENT_TRACKER_20260813_163156.md`

Tracker hiện hành sau khi kế hoạch được khóa. Tất cả mốc đều `DONE`:

| Mốc | Nhiệm vụ | Kết quả ghi nhận |
|---|---|---|
| E2-R001 | Sanity query-time/raw replay | Validator đạt 18/18, không dùng làm số liệu |
| E2-R002 | Calibration | 80 run, mọi ô QA đạt |
| E2-R003 | Validation lock | 280 run, khóa diagnostic threshold trước test |
| E2-R004 | Confirmatory evidence | 560 condition-run, 84.000 quyết định |
| E2-R005 | Integrity/report | Artifact canonical đạt 18/18, báo cáo gốc đã promote |

## 3. Thư mục `research`

Ở cấp trực tiếp, `research` hiện có thư mục `Report`. Vì vậy phần lớn nội dung nghiên cứu nằm trong `research/Report`, không phải các thư mục `research/experiments` hay `research/framework` ở cấp gốc.

### `research/Report`

Đây là vùng chứa sản phẩm nghiên cứu và báo cáo. Nó gồm:

- `Report_task1.md`: báo cáo tổng hợp về lỗi đo FPR của case `benign-on` trong thí nghiệm r2entropy và cách sửa;
- `experiments/`: mã nguồn, protocol, run registry, raw data, kết quả và báo cáo riêng của từng thí nghiệm;
- `framework/`: framework Docker dùng chung cho các profile detector và workload.

### `research/Report/framework`

Framework chuẩn hóa cách chạy baseline/ablation B0-B5 trên một topology chung, thay vì sao chép Docker lab cho từng thí nghiệm.

#### `README.md`

Tài liệu kiến trúc và hướng dẫn sử dụng. Nội dung chính:

- topology bốn container: `client`, `resolver`, `auth`, `attacker` trên mạng Docker bridge `10.70.0.0/24`;
- trách nhiệm của từng container;
- cách profile detector và workload được tổ hợp độc lập;
- feature `samples`, entropy Shannon và `unique_ratio`;
- bảng ý nghĩa B0-B5;
- vòng đời một lần chạy và cách lưu artifact;
- yêu cầu Docker/Compose và ví dụ chạy.

Framework dùng implementation testbed từ `labs/r2entropy`; nó chưa phải thí nghiệm với IP fragmentation thật, Unbound/BIND thật hoặc PCAP replay.

#### `compose.yaml`

Định nghĩa topology Docker dùng chung và cách build/kết nối các container. Đây là phần hạ tầng thực thi, không chứa kết quả phân tích.

#### `run.sh`

Script điều phối một lần chạy. Cú pháp:

```bash
bash run.sh <b0|b1|b2|b3|b4|b5> <baseline|benign|attack> [rounds]
```

Script kiểm tra tham số, nạp profile, recreate stack, bật/tắt defense và benign generator, khởi động attacker nếu cần, chạy client, sau đó sao chép result, latency, event, decision, summary, log và metadata vào `artifacts/<run-id>/<profile>/<workload>`.

#### `config/b0.env` đến `config/b5.env`

Mỗi file là một profile cấu hình detector:

| Profile | Vai trò |
|---|---|
| B0 | Không phòng vệ |
| B1 | POPS/Rℓ2 gốc, policy legacy |
| B2 | Chỉ đếm volume/samples |
| B3 | Chỉ dùng entropy |
| B4 | Chỉ dùng tỷ lệ IPID khác nhau |
| B5 | Kết hợp cả samples, entropy và unique ratio |

Ngưỡng B5 hiện tại là cửa sổ 2 giây, tối thiểu 24 mẫu, entropy tối thiểu 4,0 bit và `unique_ratio` tối thiểu 0,70.

### `research/Report/experiments`

Đây là vùng quản lý các thí nghiệm cụ thể. Mỗi thí nghiệm thường có mã nguồn ở cấp thư mục, báo cáo, rồi thư mục `runs` chứa các chiến dịch và artifact bất biến.

#### `experiments/E1`

E1 nghiên cứu khi nào B5 bắt đầu kích hoạt bảo vệ nhầm trên lưu lượng fragment hợp lệ. Nó tập trung vào FPR/false trigger theo tải và kiểu IPID:

- `random2048`: IPID ngẫu nhiên trong 2.048 giá trị;
- `sequential`: IPID tuần tự;
- `smallpool16`: IPID lặp trong nhóm 16 giá trị.

E1 thử các mức tải từ 5 đến 300 fragment/cửa sổ, mỗi ô có 20 lần chạy độc lập và 300 quyết định/run. Kết luận chính: với IPID ngẫu nhiên/tuần tự, vùng chuyển rõ nằm khoảng 18-24 fragment trong 2 giây; với IPID lặp, B5 ít bật hơn nhưng có thể tạo điểm mù. Đây vẫn là controlled emulation, không phải bằng chứng an ninh đầu-cuối.

Các file đáng chú ý:

- `E1_report.md`: báo cáo diễn giải, bảng FPR, giới hạn và các câu được phép/không được phép dùng;
- `runs/E1_confirmatory_20260810_seed20260810_raw_v2/`: artifact xác nhận, gồm protocol, raw decisions, CSV, JSON, figures, source snapshot và validation;
- `runs/.../raw_decisions/`: dữ liệu quyết định chi tiết theo condition, mức tải và run;
- `runs/.../figures/`: hình minh họa kết quả.

#### `experiments/E2`

E2 kiểm tra trực tiếp liệu entropy và `unique_ratio` có tạo thêm khả năng phân biệt ngoài volume-only B2 hay không. E2 dùng thiết kế ghép cặp: benign và attack chia sẻ timestamp trace, mức tải, query schedule và cửa sổ quan sát; khác biệt chính nằm ở phân phối IPID.

Các thành phần ở cấp thư mục:

- `e2_confirmatory.py`: tạo/chạy chiến dịch E2;
- `e2_validate.py`: kiểm tra độc lập raw replay, tính năng, quyết định, tính toàn vẹn và artifact;
- `e2_report.py`: tạo báo cáo từ kết quả;
- `E2_report.md`: báo cáo kết quả và diễn giải;
- `ARTIFACT_STATUS.md`: chỉ rõ artifact canonical, phạm vi claim được phép và các artifact lịch sử không được trích dẫn.

Các thư mục con quan trọng:

- `runs/`: registry và toàn bộ lần chạy;
- `runs/E2_confirmatory_20260814_complete_b0_ablation/`: artifact canonical cần dùng cho kết luận E2, có protocol, raw runs, CSV/JSON tổng hợp, source snapshot, manifest và validation PASS 18/18;
- `runs/E2_confirmatory_20260813_165220_seed20260813/`: artifact xác nhận cũ, còn tái lập được nhưng đã bị bản canonical thay thế;
- `runs/smoke_e2_confirmatory_20260813_1638/`: smoke test triển khai, không phải kết quả nghiên cứu;
- `runs/provisional/`: snapshot thăm dò, chỉ giữ để truy xuất lịch sử, không dùng làm bằng chứng xác nhận;
- `archive/`: tài liệu tạm thời hoặc bản cũ được lưu để truy vết, không phải nguồn kết luận hiện hành.

Kết luận E2: tại operating point `24/4,0/0,70`, B5 không vượt B2 trên các sweep chính; B5 còn kém B2 trong probe IPID cố định/lặp. `unique_ratio` có tín hiệu xếp hạng tốt ở tải cao khi hiệu chỉnh ngưỡng riêng, nhưng điều đó chưa chứng minh B5 với ngưỡng cố định hiện tại tốt hơn B2.

### `research/Report/framework/config` và artifact

Các file cấu hình quyết định behavior của detector, còn artifact là bằng chứng đầu ra. Không nên trộn hai vai trò:

- sửa profile/config để định nghĩa một protocol hoặc operating point mới;
- chạy framework/experiment để sinh artifact mới với `RUN_ID` riêng;
- dùng validator để xác nhận raw, aggregate và provenance;
- chỉ dùng artifact canonical/được promote khi viết kết luận.

## 4. `Report_task1.md` và lưu ý chất lượng

`research/Report/Report_task1.md` là báo cáo về case `r2entropy/benign-on` ban đầu không phát FRAG2 hợp lệ. Vì không có FRAG2, entropy trên tập rỗng bằng 0 và kết quả `150 allow / 0 block` không đủ để chứng minh FPR. Báo cáo mô tả bản sửa tại `labs/r2entropy/auth/auth_server.py`, trong đó auth phát thêm FRAG2 hợp lệ cho case `benign-on`; sau sửa entropy khoảng 2,4 bit và quyết định vẫn `150 allow / 0 block`.

Lưu ý: file này hiện còn dấu phân cách merge conflict (`<<<<<<<`, `=======`, `>>>>>>>`) trong phần giữa tài liệu. Đây là dấu hiệu báo cáo chưa được dọn hoàn toàn và cần xử lý trước khi dùng làm tài liệu chính thức.

## 5. Trạng thái và cách đọc đúng

1. Khi cần biết protocol hiện hành, đọc `refine-logs/EXPERIMENT_PLAN_20260813_163156.md`.
2. Khi cần biết trạng thái các mốc, đọc `refine-logs/EXPERIMENT_TRACKER_20260813_163156.md`.
3. Khi cần chạy testbed chung, đọc `research/Report/framework/README.md` và dùng `framework/run.sh`.
4. Khi cần kết luận E1, dùng `experiments/E1/E1_report.md` cùng artifact xác nhận của E1.
5. Khi cần kết luận E2, ưu tiên `experiments/E2/ARTIFACT_STATUS.md`, sau đó dùng artifact canonical và `experiments/E2/E2_report.md`.
6. Không dùng smoke, provisional hoặc artifact đã superseded làm bằng chứng confirmatory.

Có một khác biệt số lượng cần ghi nhớ: tracker E2 hiện hành tóm tắt phần test là 560 condition-run và 84.000 quyết định, trong khi báo cáo/artifact canonical E2 ghi toàn chiến dịch là 920 run và 138.000 quyết định. Hai con số có thể tương ứng với các phạm vi đếm khác nhau (phần test so với toàn chiến dịch), nhưng nên kiểm tra protocol/manifest khi cần trích dẫn chính xác.

## 6. Các giới hạn chung

- Phần lớn bằng chứng hiện tại là controlled synthetic emulation.
- Chưa được phép suy ra trực tiếp khả năng ngăn DNS poisoning, ASR, BFrag coverage, latency, CPU, memory, throughput hoặc deployment performance.
- E5/thiết lập resolver thật với IP fragmentation thật vẫn cần thiết cho claim end-to-end.
- Threshold hiện tại là operating point đang được đánh giá, chưa phải ngưỡng tối ưu cuối cùng.
