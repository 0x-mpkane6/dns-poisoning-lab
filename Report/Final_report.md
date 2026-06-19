# Báo cáo kết quả chạy lại OoB và SFrag với 150 query

## 1. Sơ bộ

Kết quả có hai mode: `weak` dùng để minh họa cơ chế attack thắng race khi entropy bị làm yếu, còn `bruteforce` dùng source port random và sát hơn với giả định blind brute-force trong paper.

## 2. Thiết lập

Hai lab được chạy là `oob` và `sfrag`. Mỗi lab có ba case: `baseline` không bật attacker, `attack-off` bật attacker nhưng tắt defense, và `attack-on` bật cả attacker lẫn defense. Metric chính là ASR, tức tỷ lệ query bị poison.

Nguồn dữ liệu: `Report/data/docker_weak_150/p2_metrics.csv` và `Report/data/docker_bruteforce_150/p2_metrics.csv`.

## 3. Triển khai các kịch bản tấn công

### 3.1. Nhóm S-type

Nhóm S-type được triển khai trong `labs/stype` với ba biến thể: TXID brute-force, source-port brute-force và Kaminsky-style. Điểm chung của ba biến thể là attacker gửi các DNS response giả mạo mang địa chỉ nguồn của authoritative server về resolver trong khoảng thời gian authoritative response đang bị trì hoãn `0.25` giây. Client thực hiện `150` vòng đo; trước mỗi vòng, cache được làm sạch bằng truy vấn điều khiển để mỗi lần thử độc lập với kết quả trước đó. Mỗi cửa sổ truy vấn sử dụng ngân sách `200` response giả.

Với **TXID brute-force**, resolver cố định upstream source port tại `33333` và chọn TXID trong không gian `0..199`. Attacker giữ cố định qname `bank.com`, destination port `33333`, sau đó gửi lần lượt `200` response ứng với toàn bộ TXID có thể. Response giả trả về `bank.com -> 6.6.6.6`; nếu một response đến trước authoritative response và có TXID khớp, resolver sẽ cache địa chỉ độc.

Với **source-port brute-force**, qname vẫn được cố định là `bank.com`, nhưng resolver chọn source port trong dải `33300..33319` và TXID trong dải `0..9`. Attacker quét tích Descartes của hai không gian này, tương ứng `20 port x 10 TXID = 200 response`. Cấu hình thu nhỏ này cho phép minh họa đồng thời ảnh hưởng của source-port entropy và TXID entropy trong giới hạn tài nguyên của Docker lab.

Với **Kaminsky-style**, resolver sử dụng source port cố định `33333`, TXID trong không gian `0..199` và client kích hoạt cache miss bằng qname `victim.bank.com`. Attacker gửi `200` response giả để brute-force TXID; phần answer trả lời cho tên đang được hỏi, trong khi additional section chèn `bank.com -> 6.6.6.6`. Khi thắng race, resolver cache additional record và các truy vấn `bank.com` sau đó trả về IP của attacker.

### 3.2. Nhóm fragmentation-based

Nhóm fragmentation-based gồm SFrag và BFrag, được triển khai trong `labs/sfrag` và `labs/bfrag`. Authoritative server gắn metadata `TYPE=FRAG1;IPID=<value>` vào response của các query có tiền tố `frag`, trong khi attacker gửi response giả mang marker `TYPE=FRAG2`, IPID tương ứng và A record `bank.com -> 6.6.6.6`. Resolver lưu frag2 trong một khoảng thời gian ngắn; nếu frag1 và frag2 có IPID khớp khi defense tắt, record giả được ghép vào response và đưa vào cache. Authoritative server sử dụng delay `0.25` giây để tạo cửa sổ race, còn attacker lặp flood với khoảng nghỉ mặc định `0.02` giây.

Trong **SFrag**, IPID của frag1 được authoritative server chọn ngẫu nhiên. Ở cấu hình đầy đủ, IPID nằm trong không gian `0..65534`, TXID sử dụng đủ `65536` giá trị và source port upstream do hệ điều hành chọn ngẫu nhiên. Attacker phải thử nhiều IPID, đồng thời có thể phải quét thêm dải source port. Để tái hiện attack trong một phiên Docker ngắn, mode `weak` cố định source port upstream tại `33333` và giảm `IPID_SPACE` từ `65535` xuống `2048`; attacker chỉ cần quét một port đã biết và toàn bộ `2048` IPID. Mode `bruteforce` giữ source port ngẫu nhiên, dùng IPID đầy đủ và cho attacker quét dải port `1024..65535`, vì vậy chi phí lớn hơn đáng kể.

Trong **BFrag**, IPID không được đoán ngẫu nhiên mà được đặt cố định bằng `BULLSEYE_IPID=777` ở cả authoritative server và attacker. Attacker liên tục gửi frag2 có IPID `777`, destination port ứng viên và record độc. Kịch bản này biểu diễn trường hợp attacker đã suy ra hoặc biết trước IPID mục tiêu, nên không cần quét toàn bộ không gian IPID như SFrag. Các tham số TXID, source port và auth delay vẫn được giữ cùng mô hình để tạo race có kiểm soát.

### 3.3. Nhóm out-of-bailiwick

Kịch bản SOoB được triển khai trong `labs/oob`. Client liên tục tạo qname mới thuộc zone `example.net` để buộc resolver gửi truy vấn upstream. Attacker giả mạo địa chỉ nguồn của authoritative server và flood response về source port của resolver. Response giả chứa answer phù hợp với truy vấn mục tiêu, đồng thời chèn A record ngoài bailiwick `bank.com -> 6.6.6.6` vào additional section. Khi defense tắt, resolver lỏng có thể cache tất cả A record trong response, khiến truy vấn `bank.com` trả về IP độc. Ngoài profile mặc định, lab còn hỗ trợ profile `multi` để thử thêm NS hijack và sibling poisoning.

Cấu hình mặc định gần thực tế sử dụng TXID `16-bit` với `TXID_SPACE=65536` và `UPSTREAM_FIXED_SRC_PORT=0`, nghĩa là hệ điều hành chọn source port ngẫu nhiên. Attacker mặc định chỉ có ngân sách quét hữu hạn `TXID_SCAN_LIMIT=4096`. Trong mode `weak`, upstream source port được cố định tại `33333`, không gian TXID giảm xuống `1024` và attacker quét đủ `1024` giá trị với chu kỳ flood `0.03` giây. Nhờ vậy attacker có xác suất thắng race cao trong lab. Trong mode `bruteforce`, resolver tiếp tục dùng source port ngẫu nhiên và TXID đầy đủ, còn attacker phải quét dải source port `1024..65535` kết hợp với `65536` TXID, phản ánh rõ chi phí của blind brute-force khi entropy không bị làm yếu.

Ba nhóm tấn công đều dùng `203.0.113.80` làm địa chỉ hợp lệ của `bank.com` và `6.6.6.6` làm địa chỉ poisoning. Việc phân biệt hai giá trị này trong `result.txt` là cơ sở để tính Attack Success Rate ở các phần kết quả.

## 4. Cách làm yếu cấu hình

- So với cấu hình sát bài nghiên cứu, mode `weak` chủ động giảm entropy để attack có thể thắng race trong một lab Docker ngắn. Cụ thể, resolver không dùng source port ngẫu nhiên mà cố định port upstream ở `33333`; không gian TXID của OoB giảm từ `65536` xuống `1024`; không gian IPID của SFrag giảm từ `65535` xuống `2048`. Attacker vì vậy chỉ cần quét một port đã biết và một không gian TXID/IPID nhỏ hơn rất nhiều.

- Ngược lại, mode `bruteforce` giữ source port random và để attacker quét dải source-port candidate `1024..65535` cùng TXID/IPID đầy đủ. Vì vậy `weak` nên được hiểu là cấu hình demo để kiểm chứng cơ chế tấn công/phòng thủ, còn `bruteforce` là cấu hình dùng để đánh giá độ khó khi entropy gần với giả định trong bài nghiên cứu hơn.

## 5. Bảng số liệu tổng hợp

| Mode | Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| weak | OoB | baseline | 0 / 150 | 0.00% | 274.846 ms | 274.278 ms |
| weak | OoB | attack-off | 148 / 150 | 98.67% | 260.647 ms | 376.623 ms |
| weak | OoB | attack-on | 0 / 150 | 0.00% | 254.951 ms | 382.839 ms |
| weak | SFrag | baseline | 0 / 150 | 0.00% | 271.194 ms | 271.535 ms |
| weak | SFrag | attack-off | 147 / 150 | 98.00% | 271.229 ms | 272.730 ms |
| weak | SFrag | attack-on | 0 / 150 | 0.00% | 275.347 ms | 274.763 ms |
| bruteforce | OoB | baseline | 0 / 150 | 0.00% | 277.595 ms | 273.263 ms |
| bruteforce | OoB | attack-off | 0 / 150 | 0.00% | 277.588 ms | 274.090 ms |
| bruteforce | OoB | attack-on | 0 / 150 | 0.00% | 277.655 ms | 274.598 ms |
| bruteforce | SFrag | baseline | 0 / 150 | 0.00% | 277.537 ms | 273.299 ms |
| bruteforce | SFrag | attack-off | 0 / 150 | 0.00% | 280.277 ms | 273.036 ms |
| bruteforce | SFrag | attack-on | 0 / 150 | 0.00% | 277.769 ms | 275.585 ms |

## 6. Nhận xét

- Với `weak`, attack-off đạt ASR rất cao ở cả OoB và SFrag, còn attack-on về 0%.
- Với `bruteforce`, cả OoB và SFrag đều không poison được trong 150 query.
- Chênh lệch giữa hai mode cho thấy entropy của source port/TXID/IPID là yếu tố quyết định độ khó của blind brute-force.

## 7. Kết luận

Kết quả `weak` phù hợp để minh họa tác dụng của rule phòng thủ vì attack thắng rõ khi defense off và về 0% khi defense on. Kết quả `bruteforce` phản ánh cấu hình sát thực tế hơn: khi entropy được mở rộng, batch 150 query không ghi nhận poisoning ở cả OoB và SFrag.
