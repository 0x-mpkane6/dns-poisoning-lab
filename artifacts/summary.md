# Tổng hợp kết quả thực nghiệm

Mỗi kịch bản gồm `150` mẫu. Ba metric được trình bày là Attack Success Rate (ASR), latency trung bình và latency p95. Số liệu SFrag, BFrag và OoB sử dụng profile `weak`; các số liệu còn lại lấy trực tiếp từ artifact của từng biến thể S-type.

## Baseline

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 299.205 | 291.824 |
| Source-port brute-force | 0.00% | 320.214 | 294.206 |
| Kaminsky-style | 0.00% | 298.750 | 291.998 |
| SFrag (`weak`) | 0.00% | 271.194 | 271.535 |
| BFrag (`weak`) | 0.00% | 281.764 | 277.001 |
| Out-of-Bailiwick (`weak`) | 0.00% | 274.846 | 274.278 |

## Attack-off

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 21.363 | 37.787 |
| Source-port brute-force | 0.00% | 18.118 | 28.921 |
| Kaminsky-style | 23.33% | 20.117 | 31.485 |
| SFrag (`weak`) | 98.00% | 271.229 | 272.730 |
| BFrag (`weak`) | 100.00% | 280.248 | 273.955 |
| Out-of-Bailiwick (`weak`) | 98.67% | 260.647 | 376.623 |

## Attack-on

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 21.958 | 36.979 |
| Source-port brute-force | 0.00% | 16.803 | 29.399 |
| Kaminsky-style | 0.00% | 20.828 | 32.293 |
| SFrag (`weak`) | 0.00% | 275.347 | 274.763 |
| BFrag (`weak`) | 0.00% | 283.898 | 275.370 |
| Out-of-Bailiwick (`weak`) | 0.00% | 254.951 | 382.839 |

## Rl2 cải tiến dựa trên entropy

Lab `r2entropy` không có case `benign-off`; ba case thực tế là `baseline`, `benign-on` và `attack-on`. Entropy trung bình được tính từ trường `entropy` trong `r2_entropy_decisions.jsonl`.

| Case | ASR | Entropy IPID trung bình | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 0.00% | N/A | 314.476 | 288.744 |
| Benign-on | 0.00% | 0.000 | 275.479 | 287.106 |
| Attack-on | 0.00% | 10.836 | 304.422 | 279.118 |

Baseline không chứa frag1/frag2 nên resolver không tạo entropy decision. Trong `benign-on`, cả `150/150` decision đều là `allow`. Trong `attack-on`, entropy trung bình `10.836` vượt ngưỡng cấu hình `4.0` và cả `148/148` decision được ghi nhận là `tc_block`. Kết quả cho thấy rule không chặn luồng fragment hợp lệ nhưng phát hiện được SFrag flood có phân bố IPID hỗn loạn.

## Nguồn dữ liệu

- `artifacts/txid/`
- `artifacts/port/`
- `artifacts/kaminsky/`
- `artifacts/sfrag-weak/`
- `artifacts/bfrag-weak/`
- `artifacts/oob-weak/`
- `artifacts/r2entropy/`
