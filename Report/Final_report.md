# Báo cáo kết quả chạy lại OoB, SFrag và BFrag với 150 query

## 1. Sơ bộ

Kết quả có hai mode: `weak` dùng để minh họa cơ chế attack thắng race khi entropy bị làm yếu, còn `bruteforce` dùng source port random và sát hơn với giả định blind brute-force trong paper.

## 2. Thiết lập

Ba lab được chạy là `oob`, `sfrag` và `bfrag`. Mỗi lab có ba case: `baseline` không bật attacker, `attack-off` bật attacker nhưng tắt defense, và `attack-on` bật cả attacker lẫn defense. Metric chính là ASR, tức tỷ lệ query bị poison.

Nguồn dữ liệu: `Report/data/docker_weak_150/p2_metrics.csv` và `Report/data/docker_bruteforce_150/p2_metrics.csv`.

## 3. Cách làm yếu cấu hình

- So với cấu hình sát bài nghiên cứu, mode `weak` chủ động giảm entropy để attack có thể thắng race trong một lab Docker ngắn. Cụ thể, resolver không dùng source port ngẫu nhiên mà cố định port upstream ở `33333`; không gian TXID của OoB giảm từ `65536` xuống `1024`; không gian IPID của SFrag giảm từ `65535` xuống `2048`. Với BFrag, lab giữ giả định bullseye bằng `BULLSEYE_IPID=777`, nên điểm làm yếu quan trọng nhất vẫn là source port cố định.

- Ngược lại, mode `bruteforce` giữ source port random và để attacker quét dải source-port candidate `1024..65535`. Với OoB/SFrag, attacker còn phải đi cùng không gian TXID/IPID đầy đủ; với BFrag, attacker đã biết IPID bullseye nên phần brute-force chính là source port. Vì vậy `weak` nên được hiểu là cấu hình demo để kiểm chứng cơ chế tấn công/phòng thủ, còn `bruteforce` là cấu hình dùng để đánh giá độ khó khi entropy gần với giả định trong bài nghiên cứu hơn.

## 4. Bảng số liệu tổng hợp

| Mode | Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| weak | OoB | baseline | 0 / 150 | 0.00% | 274.846 ms | 274.278 ms |
| weak | OoB | attack-off | 148 / 150 | 98.67% | 260.647 ms | 376.623 ms |
| weak | OoB | attack-on | 0 / 150 | 0.00% | 254.951 ms | 382.839 ms |
| weak | SFrag | baseline | 0 / 150 | 0.00% | 271.194 ms | 271.535 ms |
| weak | SFrag | attack-off | 147 / 150 | 98.00% | 271.229 ms | 272.730 ms |
| weak | SFrag | attack-on | 0 / 150 | 0.00% | 275.347 ms | 274.763 ms |
| weak | BFrag | baseline | 0 / 150 | 0.00% | 281.764 ms | 277.001 ms |
| weak | BFrag | attack-off | 150 / 150 | 100.00% | 280.248 ms | 273.955 ms |
| weak | BFrag | attack-on | 0 / 150 | 0.00% | 283.898 ms | 275.370 ms |
| bruteforce | OoB | baseline | 0 / 150 | 0.00% | 277.595 ms | 273.263 ms |
| bruteforce | OoB | attack-off | 0 / 150 | 0.00% | 277.588 ms | 274.090 ms |
| bruteforce | OoB | attack-on | 0 / 150 | 0.00% | 277.655 ms | 274.598 ms |
| bruteforce | SFrag | baseline | 0 / 150 | 0.00% | 277.537 ms | 273.299 ms |
| bruteforce | SFrag | attack-off | 0 / 150 | 0.00% | 280.277 ms | 273.036 ms |
| bruteforce | SFrag | attack-on | 0 / 150 | 0.00% | 277.769 ms | 275.585 ms |
| bruteforce | BFrag | baseline | 0 / 150 | 0.00% | 277.931 ms | 274.367 ms |
| bruteforce | BFrag | attack-off | 0 / 150 | 0.00% | 284.564 ms | 273.394 ms |
| bruteforce | BFrag | attack-on | 0 / 150 | 0.00% | 283.307 ms | 275.458 ms |

## 5. Nhận xét

- Với `weak`, attack-off đạt ASR rất cao ở cả ba lab: OoB, SFrag và BFrag; attack-on đều về 0%.
- Với `bruteforce`, cả ba lab đều không poison được trong 150 query.
- Chênh lệch giữa hai mode cho thấy entropy của source port/TXID/IPID là yếu tố quyết định độ khó của blind brute-force.

## 6. Kết luận

Kết quả `weak` phù hợp để minh họa tác dụng của rule phòng thủ vì attack thắng rõ khi defense off và về 0% khi defense on. Kết quả `bruteforce` phản ánh cấu hình sát thực tế hơn: khi entropy được mở rộng, batch 150 query không ghi nhận poisoning ở OoB, SFrag và BFrag.
