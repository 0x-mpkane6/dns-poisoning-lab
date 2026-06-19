# Tổng hợp kết quả thực nghiệm

Mỗi kịch bản gồm `150` mẫu. Ba metric được trình bày là Attack Success Rate (ASR), latency trung bình và latency p95. Số liệu SFrag và OoB sử dụng profile `weak`; các số liệu còn lại lấy trực tiếp từ artifact của từng biến thể S-type.

## Baseline

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 299.205 | 291.824 |
| Source-port brute-force | 0.00% | 320.214 | 294.206 |
| Kaminsky-style | 0.00% | 298.750 | 291.998 |
| SFrag (`weak`) | 0.00% | 271.194 | 271.535 |
| Out-of-Bailiwick (`weak`) | 0.00% | 274.846 | 274.278 |

## Attack-off

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 21.363 | 37.787 |
| Source-port brute-force | 0.00% | 18.118 | 28.921 |
| Kaminsky-style | 23.33% | 20.117 | 31.485 |
| SFrag (`weak`) | 98.00% | 271.229 | 272.730 |
| Out-of-Bailiwick (`weak`) | 98.67% | 260.647 | 376.623 |

## Attack-on

| Kiểu tấn công | ASR | Latency trung bình (ms) | Latency p95 (ms) |
| --- | ---: | ---: | ---: |
| TXID brute-force | 0.00% | 21.958 | 36.979 |
| Source-port brute-force | 0.00% | 16.803 | 29.399 |
| Kaminsky-style | 0.00% | 20.828 | 32.293 |
| SFrag (`weak`) | 0.00% | 275.347 | 274.763 |
| Out-of-Bailiwick (`weak`) | 0.00% | 254.951 | 382.839 |

## Nguồn dữ liệu

- `artifacts/txid/`
- `artifacts/port/`
- `artifacts/kaminsky/`
- `artifacts/sfrag-weak/`
- `artifacts/oob-weak/`

Artifact hiện tại chưa có bộ metrics BFrag nên BFrag chưa được đưa vào các bảng trên.
