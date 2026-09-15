# Hai phân tích bổ sung: kết quả và cách dùng trong bài

Đã hoàn thành hai phần. Cả hai là post-hoc; các protocol và source snapshot được lưu trước khi tổng hợp. Ngưỡng locked vẫn là (8, 6.0, 0.90).

## 1. Phân biệt benign–attack với không gian IPID 65.536

Chỉ mở validation: 27,600 quyết định từ 184 condition traces. Đã tái dựng khớp 403,593 fragment events gốc, toàn bộ n/H/U và dự đoán B2/initial B5 (sai khác đặc trưng lớn nhất bằng 0). Sau đó đổi không gian IPID từ 2.048 lên 65.536, tạo thêm 27.600 quyết định. Lịch fragment, lịch query, occupancy và vị trí benign/attack trong luồng được giữ nguyên.

Phân tích chính gồm 48 paired traces (continuous/bursty × bốn tải × sáu cặp). Tổng cộng 120 so sánh benign–attack khi tính cả fixed, duplicate-sweep và random negative control; các probe dùng lại benign trace nên không được coi 120 so sánh là 120 đơn vị độc lập. Có 16 benign-only traces trong validation, được lưu kết quả nhưng không dùng để dựng cặp attack giả. Không mở held_out_test.csv.gz và không hiệu chỉnh threshold.

| Metric | IPID 2.048 | IPID 65.536 | Chênh lệch [95% CI] |
|---|---:|---:|---|
| Entropy AP | 0.5780 | 0.5041 | -0.0739 [-0.0786, -0.0696] |
| Unique-ratio AP | 0.7512 | 0.5196 | -0.2315 [-0.2405, -0.2224] |
| B5 attack alert | 0.5911 | 0.5942 | +0.0031 [+0.0015, +0.0047] |
| B5 benign trigger | 0.5814 | 0.5936 | +0.0122 [+0.0103, +0.0144] |
| B5 FNR | 0.4089 | 0.4058 | -0.0031 [-0.0047, -0.0015] |
| B5 J | 0.0097 | 0.0006 | -0.0092 [-0.0121, -0.0067] |

AP là average precision với class mix 50/50 trong mỗi cặp; CI resample nguyên paired trace, không coi 150 quyết định trong trace là 150 mẫu độc lập. Macro J của B2 và initial B5 đều bằng 0 trong cả hai không gian, nên J của locked B5 cũng là Delta J so với B2.

**Diễn giải:** lợi thế phân biệt theo IPID của lưới controlled phụ thuộc mạnh vào không gian ID. Với 65.536 giá trị, entropy và uniqueness của benign tiến gần sweep attack; AP gần 0,5 và J của locked B5 gần 0. Cần bổ sung hạn chế này vào bài, không dùng kết quả cũ để khẳng định lợi thế bền vững với toàn bộ không gian IPv4 IPID.

## 2. Baseline orphan-fragment ratio

Baseline dùng PCAP runtime có IPv4 fragment thật. Các pseudo query/FRAG1 trong controlled emulation không thiết lập quan hệ reassembly với từng FRAG2; vì vậy không ghép hai loại dữ liệu này vào cùng một baseline table hoặc giả định mọi FRAG2 synthetic là orphan.

Đã replay 1,926,167 packet records, gồm 1,811,180 fragment observations trong scope, trên PCAP phía ngoài IPS của đủ 320 run / 16.000 trial thuộc campaign 2×2. Chỉ dùng một interface capture trước enforcement, không gộp hai interface. Vẫn giữ những lần quan sát lặp trong cùng capture; một packet hash lặp có thể là retransmission, không mặc định là một packet duy nhất. Có 16,000 query snapshots được đối chiếu bằng cách tính độc lập.

Định nghĩa O: số mảnh non-initial còn trong cửa sổ hai giây mà chưa có first fragment phù hợp, chia tổng non-initial trong cửa sổ. Key gồm src/dst/protocol/IPID. First fragment phải có offset=0 và MF=1. Head trước tail tối đa hai giây được nhận; tail đến trước head vẫn là orphan cho đến khi head thực sự được quan sát. Khi đã ghép, việc head rời cửa sổ không tự biến tail thành orphan lại. Không dùng first fragment trong tương lai.

Đã cố định hai operating point trước phân tích: n>=8 và O>=0,5; đồng thời kiểm tra độ nhạy n>=8 và O>0. Có điểm ở query start, peak O và any activation trong toàn bộ query interval. Các policy khác được giữ thành strata riêng; B0 là so sánh chính để giảm feedback từ enforcement.

| Policy B0: tải nền | Chỉ số | Ước lượng | 95% CI |
|---:|---|---:|---|
| 12 | ratio_at_query_AP | 0.5000 | [0.5000, 0.5000] |
| 12 | peak_ratio_during_query_AP | 0.5000 | [0.5000, 0.5000] |
| 12 | majority_during_query_J | 0.0000 | [0.0000, 0.0000] |
| 12 | any_during_query_J | 0.0000 | [0.0000, 0.0000] |
| 200 | ratio_at_query_AP | 0.5000 | [0.5000, 0.5000] |
| 200 | peak_ratio_during_query_AP | 0.5000 | [0.5000, 0.5000] |
| 200 | majority_during_query_J | 0.0000 | [0.0000, 0.0000] |
| 200 | any_during_query_J | 0.0000 | [0.0000, 0.0000] |

Trong 7,996 forged-tail packet signatures phân biệt theo run được log, quan sát được 7,996 trong capture, qua 8,865 capture records. Cả 7,996/7,996 signatures (100.00%) có matching first fragment ở mọi lần ingress quan sát được; 8,865/8,865 capture records cũng đã được ghép. Các số này không được gọi là số trial hay số packet gửi độc lập.

**Giới hạn:** đây là offline baseline từ log, không phải một policy đã enforce trong Docker. Không được gán malicious-answer/cache-insertion rate cho orphan policy. Việc ghép được first fragment chỉ xác nhận quan hệ fragment header, không xác thực payload tail. Lab gửi legitimate first fragment trước khi thông báo cho forged-tail sender; đây là cơ chế cần dùng để giải thích kết quả.

Capture audit: có 86 chỗ record-order khác thứ tự kernel timestamp. Đã kiểm tra cả thứ tự timestamp lẫn thứ tự record: 320/320 run có orphan ratio bằng 0 suốt toàn bộ capture trong cả hai cách. Clock-offset range giữa client monotonic và wall clock lớn nhất là 2887.794 ms, nên không chứng nhận alignment query chính xác từ phép đổi clock này. Các tỷ lệ và AP orphan vẫn xác định được vì score luôn bằng 0, không phụ thuộc việc dịch query interval trong capture. Runner sẽ dừng nếu score thay đổi mà clock chưa đủ tin cậy. r001/r002 được giữ lại với audit các lỗi phân tích; bộ cuối là posthoc-s20260912-r003. Không loại run theo hiệu quả detector.

## File để chèn vào bài

- `paper/controlled_ipid_discrimination.pdf` hoặc PNG: hình AP theo tải, font 8,5 pt ở rộng 122 mm.
- `paper/controlled_ipid_macro.tex`: bảng macro và paired difference CI.
- `paper/orphan_ratio_baseline.tex`: bảng baseline orphan trên B0.
- `paper/paper_additions.tex`: figure block, câu giới thiệu bảng và đoạn diễn giải bằng tiếng Anh.
- Các CSV đầy đủ nằm ở `controlled/` và `orphan/`; manifest chứa SHA-256 của đầu vào.

## Tái lập

Từ Code:

```powershell
python -m pytest research/Report/experiments/Followup-IPID-Orphans/test_followups.py -q
python research/Report/experiments/Followup-IPID-Orphans/analyze_followups.py --stage all
python research/Report/experiments/Followup-IPID-Orphans/render_followups.py
```

Runner giữ nguyên output đã hoàn tất. Để tái tính hoàn toàn, dùng một output run ID mới trong một bản sao script và đăng ký snapshot mới; không ghi đè evidence hiện có. Bộ này không commit/push hoặc sửa bản Cloud.
