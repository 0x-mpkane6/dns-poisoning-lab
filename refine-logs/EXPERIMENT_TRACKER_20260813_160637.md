# Experiment Tracker — E2 xác nhận

| Run ID | Milestone | Mục đích | System / Variant | Split | Metrics | Priority | Status | Ghi chú |
|---|---|---|---|---|---|---|---|---|
| E2-R001 | M0 | Sanity về thứ tự FRAG2/FRAG1 và raw replay | Query-timed simulator, B1–B5 | Seed sanity riêng | raw replay, timing invariant | MUST | TODO | Không dùng làm kết quả báo cáo |
| E2-R002 | M1 | Freeze rate scale | 6 condition × 4 levels | Calibration K=10 | samples/window | MUST | TODO | Seed riêng, không phải seed main |
| E2-R003 | M2 | Kiểm tra volume-matching độc lập | 6 condition × 4 levels | Validation K=10 | chênh occupancy vs benign | MUST | TODO | Không retune sau validation |
| E2-R004 | M3 | Kết quả E2 xác nhận | B1–B5 | Held-out K=20, 300 decision/run | alert rate, B5−B2 bootstrap CI | MUST | TODO | 480 run / 144.000 decision |
| E2-R005 | M4 | Validator và báo cáo dễ hiểu | E2 result artifact | Held-out data only | raw→aggregate, claim gate | MUST | TODO | Chỉ gọi controlled emulation |
