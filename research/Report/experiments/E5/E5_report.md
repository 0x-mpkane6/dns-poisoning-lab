# E5-Unbound — số liệu bổ sung theo outline

Đã hoàn thành ngày 28/08/2026. Phạm vi: bốn ca E5 và B0 đối chứng sẵn có;
không thêm C5, baseline mới, quét boundary hay đợt PCAP.

- Unbound 1.26.1 với fragment IPv4 thật trong Docker.
- B5 giữ nguyên `N=8`, `H=6.0`, `U=0.90`, cửa sổ 2 giây.
- 20 lần chạy/cấu hình × 5 cấu hình = **100 lần chạy chính thức**.
- 50 vòng truy vấn/lần chạy = **5.000 lượt kiểm tra bank.com**.
- 5 lượt sanity được giữ riêng, không gộp vào kết quả chính.
- Sanity: **PASS 225/225**; chính thức: **PASS 4.500/4.500**, không lỗi dữ liệu.

## Kết quả chính

Các tỷ lệ là trung bình theo lần chạy. ASR là tỷ lệ câu trả lời bank.com chứa
địa chỉ đầu độc; tỷ lệ kích hoạt là tỷ lệ decision-event yêu cầu chặn, không phải
tỷ lệ gói đã bị firewall loại bỏ.

| Ca | Số run | ASR | Tỷ lệ yêu cầu chặn | Mẫu/cửa sổ | Entropy (bit) | Unique ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| C0 — B0 đối chứng đầu độc | 20 | 100% | 0% | 17,83 | 3,826 | 0,9625 |
| C1 — Benign thấp | 20 | 0% | 0% | 22,38 | 4,310 | 0,9920 |
| C2 — Benign gần boundary E1 cũ | 20 | 0% | 0% | 40,85 | 5,285 | 0,9865 |
| C3 — Attack IPID cố định, volume-matched | 20 | 100% | 0% | 40,71 | 0 | 0,0260 |
| C4 — Flood, B5 | 20 | 100% | 100% | 421,38 | 8,627 | 0,9946 |

Nhận định:

- **C0 xác nhận đường đầu độc hoạt động:** khi tắt phòng vệ, ASR đạt 100%.
  Đối chứng này cho thấy testbed tạo được kết quả đầu độc, nên các ca bật B5 có
  một mốc kiểm tra đường tấn công thực sự hoạt động.
- **C1/C2 chưa ghi nhận bật nhầm:** B5 không yêu cầu chặn ở cả hai mức tải hợp lệ.
  Tuy nhiên, ASR bằng 0 ở đây không chứng minh khả năng chống tấn công, vì hai ca
  này không chứa dữ liệu đầu độc. Kết luận chỉ áp dụng cho hai mức tải đã thử.
- **C2/C3 gần nhau về lượng fragment:** số mẫu trung bình chỉ lệch **0,344%**,
  dưới giới hạn 15% đã định trước. Vì vậy, khi đối chiếu hai ca, cần xem xét cả
  cách IPID thay đổi, không chỉ tổng số fragment.
- **C3 thể hiện hạn chế trước IPID cố định:** entropy bằng 0 và unique ratio
  khoảng 0,0260 đều dưới ngưỡng B5. Luật không kích hoạt dù lượng fragment gần
  C2, trong khi ASR đạt 100%. Mẫu tấn công có IPID cố định đã khớp vẫn bị bỏ qua.
- **C4 phân biệt rõ yêu cầu chặn với bảo vệ thành công:** tỷ lệ yêu cầu chặn đạt
  100% nhưng ASR vẫn là 100%. Detector kích hoạt không đồng nghĩa dữ liệu đầu độc
  đã bị loại bỏ; chưa thể kết luận B5 ngăn được flood trên cấu hình Unbound này.
- **Các giá trị 0%/100% không phải bảo đảm tuyệt đối:** CI bootstrap thu về một
  điểm vì 20 run có cùng tỷ lệ quan sát. Với chỉ báo có ít nhất một sự kiện/run,
  exact binomial CI 95% vẫn là **[0%; 16,84%] cho 0/20** và
  **[83,16%; 100%] cho 20/20**; xác suất thật chưa được xác định bằng đúng 0 hoặc 1.

## Chỉ số hệ thống

Giá trị dưới đây là trung bình các thống kê theo run. CSV/JSON có CI 95% bootstrap
5.000 lần theo run cho từng chỉ số.

Trigger là truy vấn kích hoạt tới example.net; Bank là truy vấn kiểm tra bank.com.
p50 là trung vị, còn p95/p99 mô tả phần đuôi trễ — những lượt chậm hơn phần lớn
truy vấn. Các phân vị được tính trong từng run rồi lấy trung bình, không tính
bằng cách gộp toàn bộ truy vấn thành các mẫu độc lập.

| Ca | Trigger p50/p95/p99 (ms) | Bank p50/p95/p99 (ms) | Vòng/s | Fragment quan sát/s | CPU (%) | RAM (MiB) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| C0 | 42,75 / 62,42 / 87,40 | 20,50 / 32,42 / 85,20 | 9,45 | 9,39 | 10,16 | 62,27 |
| C1 | 42,50 / 73,33 / 109,79 | 20,50 / 32,87 / 193,46 | 8,92 | 11,54 | 9,90 | 62,24 |
| C2 | 41,75 / 71,57 / 102,94 | 20,00 / 30,50 / 211,24 | 9,03 | 21,00 | 13,88 | 62,23 |
| C3 | 43,25 / 88,20 / 277,29 | 21,00 / 33,70 / 99,19 | 8,56 | 20,87 | 13,63 | 62,41 |
| C4 | 42,75 / 58,88 / 83,36 | 21,00 / 31,33 / 95,14 | 9,20 | 204,55 | 80,37 | 63,30 |

Nhận định:

- **Trung vị độ trễ gần nhau giữa các ca:** Trigger p50 nằm trong khoảng
  41,75–43,25 ms và Bank p50 khoảng 20–21 ms. Các chênh lệch nhỏ này chưa đủ để
  khẳng định cấu hình nào nhanh hơn, nhất là khi đồng hồ client có độ phân giải
  10 ms.
- **Chỉ nhìn p50 sẽ bỏ sót các lượt chậm:** C3 có Trigger p99 cao nhất bảng,
  277,29 ms; C2 có Bank p99 cao nhất, 211,24 ms. Dù trung vị gần nhau, phần đuôi
  trễ vẫn khác nhau; bảng chưa xác định nguyên nhân của những lượt chậm này.
- **CPU tăng rõ ở ca flood:** C4 dùng trung bình 80,37% CPU, so với
  9,90–13,88% ở C0–C3, đồng thời có tốc độ fragment quan sát cao nhất. Đây là mức
  sử dụng trong từng workload, không phải chi phí riêng của B5, vì các ca không
  có cùng tải và không tạo thành phép so sánh overhead ghép cặp.
- **Bộ nhớ ít thay đổi hơn CPU:** RAM trung bình nằm trong khoảng
  62,23–63,30 MiB giữa các ca. Trong phạm vi đo này, khác biệt tài nguyên nổi bật
  nằm ở CPU; chưa thể suy ra bộ nhớ sẽ ổn định khi chạy lâu hoặc tăng tải hơn nữa.
- **Vòng/s chỉ mô tả nhịp truy vấn của phép thử:** mức 8,56–9,45 vòng/s không
  phải thông lượng tối đa của resolver. Fragment quan sát/s còn bao gồm fragment
  trả lời DNS, nên không đồng nhất với tốc độ đặt cho riêng bộ phát lưu lượng.
- **Trả lời nhanh không đồng nghĩa trả lời đúng:** C4 vẫn có độ trễ trung vị gần
  các ca khác, nhưng ASR đạt 100% ở bảng đầu. Cần đọc chỉ số tốc độ cùng với kết
  quả đầu độc; độ trễ ở đây là thời gian lệnh truy vấn và chịu ảnh hưởng cache,
  không phải chỉ thời gian của các phản hồi DNS hợp lệ.

## Phạm vi diễn giải

C1/C2 không ghi nhận bật nhầm trong đợt này. C3 vẫn bị đầu độc khi detector không
kích hoạt. C4 ghi nhận yêu cầu chặn và xác minh cài luật thành công nhưng ASR vẫn
100%; chưa xác định nguyên nhân đường thực thi không ngăn được đầu độc. Không
diễn giải kết quả này thành B5 bảo vệ hiệu quả hoặc sẵn sàng triển khai.

Các vòng trong một run chịu ảnh hưởng cache, không phải 50 cuộc tấn công độc lập.
Giữ nguyên đường tấn công có kiểm soát của testbed cũ, không coi đây là đoán IPID
ngoài đường đi. C0 là positive control, không phải đối chứng flood ghép cặp với C4.

Đợt bổ sung sửa phát trùng sender theo tốc độ, dùng đồng hồ đơn điệu và chốt
phạm vi thời gian đo. Vì thế không gộp hoặc thay âm thầm số liệu đợt cũ.

## Tệp kết quả

- [CSV tổng hợp](output/E5-unbound-supplement-20260828-s202608281/e5_summary_confirmatory.csv)
- [JSON tổng hợp, CI đầy đủ](output/E5-unbound-supplement-20260828-s202608281/e5_summary_confirmatory.json)
- [Số liệu từng run](output/E5-unbound-supplement-20260828-s202608281/metrics_confirmatory.json)
- [Kiểm định chính thức](output/E5-unbound-supplement-20260828-s202608281/validation_confirmatory.json)
- [Kiểm định sanity](output/E5-unbound-supplement-20260828-s202608281/validation_sanity.json)
- [Protocol](output/E5-unbound-supplement-20260828-s202608281/e5_protocol.json)
- [Phương pháp tổng hợp và hash đầu vào](output/E5-unbound-supplement-20260828-s202608281/analysis_metadata.json)

## Chạy lại

Từ thư mục E5, bật Docker và dùng mã run mới để không ghi đè số liệu đã có:

```sh
python run_e5.py --stage all --run-id TEN_RUN_MOI
```

Công cụ và môi trường chạy nằm trong `tools/`; kết quả được ghi vào
`output/TEN_RUN_MOI/`. Lệnh `python run_e5.py --help` hiển thị các tùy chọn.
