# E5 Routed-IPS — confirmatory runtime và root-cause validation

**Cập nhật:** 02/09/2026
**Protocol:** `E5-routed-s20260902-r001`
**Implementation lock:** commit `488dd3a`

E5 là campaign runtime được thiết kế để phân biệt bốn nguyên nhân có
thể làm thất bại bảo vệ DNS cache poisoning: detector không trigger, packet
enforcement không thực thi, fallback transport thất bại, hoặc resolver/cache
không xử lý đúng kết quả. E3 và operating point `B5=(N=8,H=6.0,U=0.90)` được
giữ nguyên; E5 không retune threshold và không pool với E1–E4.
Toàn bộ kết quả dưới đây chỉ áp dụng cho testbed và workload đã đăng ký.

## Kiến trúc và semantics policy

Testbed gồm client, Unbound 1.26.1 recursive resolver, authoritative DNS server,
external attacker và một IPS/router hai interface nối hai upstream network.
Resolver truy vấn authoritative server qua IPS; mọi forged fragment từ attacker
đều phải đi qua IPS. Auth server hỗ trợ UDP và TCP port 53, trong đó TCP luôn
trả lời legitimate unfragmented answer. E5 không có resolver-local poisoner:
auth chỉ gửi metadata qua notify channel và chỉ external attacker gửi forged
tail.

IPS dùng NFQUEUE trên `FORWARD`; không có fallback implementation. Preflight đã
xác nhận kernel hỗ trợ NFQUEUE, routing hoạt động và packet counter tăng trước
khi thu dữ liệu. Mỗi trial dùng qname riêng dạng
`r<rep>-t<trial>-<nonce>.bank.com`, kiểm tra cache miss trước query và cache state
sau answer. Toàn bộ stack được recreate giữa các run.

| Policy | Semantics |
| --- | --- |
| `B0_OFF` | Forward mọi fragment; positive control cho poisoning path. |
| `B1_RL2_TC` | Khi thấy fragmented DNS response, drop datagram/tail, inject UDP `TC=1` và buộc Unbound retry TCP. |
| `B5_LOCKED_TC` | Quan sát non-initial fragments trong cửa sổ 2 s với threshold cố định `8/6.0/0.90`; sau trigger dùng cùng TC mitigation như B1. |
| `RFC_DROP_NATIVE` | Drop fragmented DNS/UDP responses, không inject TC; native fallback/no-answer được giữ làm outcome hợp lệ. |

`PREARM_TAIL_DROP` chỉ được dùng trong root-cause pilot để chứng minh forged
tail đi qua enforcement path; policy này không xuất hiện trong confirmatory
campaign.

## Workload và experimental design

E5 sử dụng bốn workload đã đăng ký: `BENIGN_LOW` với occupancy ngẫu nhiên
2,5 fragment/s, `BENIGN_BOUNDARY` với 12 fragment/s,
`ATTACK_FIXED_MATCHED` với 12 fragment/s và IPID cố định 777, và
`ATTACK_SWEEP_FLOOD` với deterministic sweep ở 200 fragment/s. Mỗi replicate
dùng một arrival/IPID/qname schedule được tính trước và replay giống hệt qua
bốn policy. Mười sáu policy--workload cells được xáo trộn trong từng replicate
theo randomized complete block với seed `20260902`.

Engineering/root-cause pilot gồm bảy run và không được dùng để suy luận. Sanity
gồm một run cho mỗi 16 cells. Confirmatory gồm 20 recreated-stack runs/cell,
50 unique-qname trials/run, tổng cộng 320 runs và 16.000 trials. Client deadline
được giữ ở 2 s; timeout hoặc no-answer là outcome hợp lệ. Đơn vị độc lập là
recreated stack run, còn các so sánh paired được ghép theo `(workload, rep)`.
Bootstrap dùng 5.000 complete blocks; any-event/run dùng exact
Clopper--Pearson interval.

Mỗi trial ghi event chain từ client query, auth receive, legitimate fragment,
attacker notify/send, IPS ingress, detector decision, packet verdict, TC/TCP
fallback, resolver answer/cache state đến client answer. Detector trigger,
enforcement và resolver outcome được xử lý như các event khác nhau.

## Validation và integrity

Preflight đạt PASS. Pilot đạt PASS 7/7, sanity đạt PASS 16/16 và confirmatory
validator đạt PASS 320/320. Trong 320 confirmatory runs, `cache_before_hits=0`,
client exit code đều bằng 0, và reconstruction độc lập của B5 khớp runtime
trigger log ở mọi run. Không có `detector_miss` integrity error do thiếu event,
không có B5-window mismatch và không có qname lặp giữa các trial trong một run.

## Kết quả confirmatory

Các tỷ lệ trong bảng là trung bình theo 20 run của từng cell, ngoại trừ
`any-poison run` được báo cáo trực tiếp trên 20 run. ASR là tỷ lệ trial có
poisoned answer trong attack workload. `Legitimate answer` và `No-answer` là
tỷ lệ trial tương ứng. `B5 trigger` chỉ là detector trigger; `TC / TCP retry`
được báo cáo riêng để không đồng nhất trigger với mitigation thành công.

| Policy | Workload | ASR / any-poison run | Legitimate answer | No-answer | B5 trigger | Forged-tail drop | TC / TCP retry |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `B0_OFF` | `BENIGN_LOW` | — | 99,2% | 0,8% | 0% | — | — |
| `B0_OFF` | `BENIGN_BOUNDARY` | — | 99,6% | 0,4% | 0% | — | — |
| `B0_OFF` | `ATTACK_FIXED_MATCHED` | 97,5% / 20/20 | 1,6% | 0,9% | 0% | 0% | 0% / 0% |
| `B0_OFF` | `ATTACK_SWEEP_FLOOD` | 99,5% / 20/20 | 0% | 0,5% | 100% | 0% | 0% / 0% |
| `B1_RL2_TC` | `BENIGN_LOW` | — | 99,3% | 0,7% | — | — | 100% / 100% |
| `B1_RL2_TC` | `BENIGN_BOUNDARY` | — | 98,7% | 1,3% | — | — | 100% / 100% |
| `B1_RL2_TC` | `ATTACK_FIXED_MATCHED` | 0% / 0/20 | 99,8% | 0,2% | 0% | 98,3% | 100% / 100% |
| `B1_RL2_TC` | `ATTACK_SWEEP_FLOOD` | 0% / 0/20 | 99,2% | 0,8% | 100% | 100% | 100% / 100% |
| `B5_LOCKED_TC` | `BENIGN_LOW` | — | 99,3% | 0,7% | 0% | — | — |
| `B5_LOCKED_TC` | `BENIGN_BOUNDARY` | — | 99,7% | 0,3% | 0% | — | — |
| `B5_LOCKED_TC` | `ATTACK_FIXED_MATCHED` | 98,0% / 20/20 | 1,6% | 0,4% | 0% | 0% | 0% / 0% |
| `B5_LOCKED_TC` | `ATTACK_SWEEP_FLOOD` | 0% / 0/20 | 99,4% | 0,6% | 100% | 100% | 100% / 100% |
| `RFC_DROP_NATIVE` | `BENIGN_LOW` | — | 0% | 100% | — | — | 0% / 0% |
| `RFC_DROP_NATIVE` | `BENIGN_BOUNDARY` | — | 0% | 100% | — | — | 0% / 0% |
| `RFC_DROP_NATIVE` | `ATTACK_FIXED_MATCHED` | 0% / 0/20 | 0% | 100% | 0% | 100% | 0% / 0% |
| `RFC_DROP_NATIVE` | `ATTACK_SWEEP_FLOOD` | 0% / 0/20 | 0% | 100% | 100% | 100% | 0% / 0% |

### Root-cause interpretation

`B0_OFF` xác nhận đường poisoning hoạt động: forged tail có ingress 100% và
any-poison xảy ra ở 20/20 run của cả hai attack workload. Ở flood workload,
điều kiện B5 vẫn được quan sát ở 100%, nhưng policy tắt nên forged tail được
forward. Đây là control chứng minh detector trigger và enforcement verdict là
hai đại lượng khác nhau.

`B5_LOCKED_TC` bị bypass ở `ATTACK_FIXED_MATCHED`: detector không trigger trong
20/20 run, forged tail không bị drop và ASR trung bình là 98,0%. Trong 1.000
attack trials của cell này, 980 trial được phân loại `detector_miss`; 20/20 run
đều có ít nhất một poisoned answer. Đây là failure ở detector layer do IPID
diversity thấp, không phải bằng chứng rằng NFQUEUE hoặc TCP path không hoạt động.

Ở `ATTACK_SWEEP_FLOOD`, B5 trigger, drop forged tail, inject TC và ghi nhận TCP
retry ở 100% trial. ASR là 0; 994/1.000 trial được phân loại `mitigated` và
6/1.000 là `transport_failure`. Do đó, cùng operating point có thể bảo vệ flood
workload khi feature window vượt threshold, nhưng không bao phủ matched
fixed-IPID workload.

`B1_RL2_TC` cho ASR bằng 0 ở cả hai attack workload mà không phụ thuộc vào B5
detector. Có 998/1.000 và 992/1.000 trial lần lượt được phân loại `mitigated`
ở fixed-match và flood; các trial còn lại là transport failure. Kết quả này
chứng minh TC injection, TCP retry và legitimate answer path hoạt động trong
routed testbed.

`RFC_DROP_NATIVE` loại bỏ poisoning ở cả hai attack workload bằng cách drop
fragment, nhưng không inject TC. Trong testbed này, native fallback không tạo
được legitimate answer trước deadline nên no-answer đạt 100% ở cả benign và
attack workload. Đây là security--availability trade-off được đo trực tiếp,
không phải claim rằng policy này luôn gây thất bại ở mọi resolver.

Với any-poison event, exact 95% Clopper--Pearson interval là `[83,16%; 100%]`
cho 20/20 run và `[0%; 16,84%]` cho 0/20 run. Các khoảng này không nên được
diễn giải là xác suất thực bằng đúng 0 hoặc 1.

## Runtime measurements

Các phân vị được tính trong từng run rồi lấy trung bình giữa 20 run; 50 trial
trong một run không được xem là 50 quan sát độc lập. Query latency báo bằng ms.
CPU và memory là các phần trăm từ Docker resource sampling; `wall duration` là
thời gian hoàn thành một run, không phải throughput tối đa của Unbound.

| Policy | Workload | Query p50/p95/p99 (ms) | Wall duration (s) | CPU p95 (%) | Memory p95 (%) |
| --- | --- | ---: | ---: | ---: | ---: |
| `B0_OFF` | `BENIGN_LOW` | 334,43 / 386,25 / 804,60 | 29,48 | 0,97 | 2,15 |
| `B0_OFF` | `BENIGN_BOUNDARY` | 336,56 / 361,54 / 655,98 | 29,39 | 3,23 | 2,16 |
| `B0_OFF` | `ATTACK_FIXED_MATCHED` | 314,41 / 342,26 / 741,68 | 27,78 | 3,00 | 2,16 |
| `B0_OFF` | `ATTACK_SWEEP_FLOOD` | 329,25 / 359,60 / 576,56 | 29,22 | 46,29 | 2,22 |
| `B1_RL2_TC` | `BENIGN_LOW` | 375,84 / 407,80 / 1.007,02 | 32,21 | 1,01 | 2,16 |
| `B1_RL2_TC` | `BENIGN_BOUNDARY` | 380,85 / 435,33 / 1.228,25 | 33,10 | 3,27 | 2,16 |
| `B1_RL2_TC` | `ATTACK_FIXED_MATCHED` | 313,41 / 349,78 / 446,58 | 27,33 | 2,96 | 2,16 |
| `B1_RL2_TC` | `ATTACK_SWEEP_FLOOD` | 329,34 / 370,64 / 715,09 | 29,45 | 45,17 | 2,22 |
| `B5_LOCKED_TC` | `BENIGN_LOW` | 334,30 / 361,02 / 754,54 | 29,49 | 0,95 | 2,15 |
| `B5_LOCKED_TC` | `BENIGN_BOUNDARY` | 336,72 / 361,67 / 622,98 | 29,23 | 3,36 | 2,16 |
| `B5_LOCKED_TC` | `ATTACK_FIXED_MATCHED` | 313,72 / 343,34 / 554,62 | 27,52 | 2,95 | 2,16 |
| `B5_LOCKED_TC` | `ATTACK_SWEEP_FLOOD` | 331,58 / 372,49 / 642,71 | 29,44 | 47,10 | 2,22 |
| `RFC_DROP_NATIVE` | `BENIGN_LOW` | 2.010,70 / 2.022,05 / 2.028,09 | 31,27 | 1,90 | 2,16 |
| `RFC_DROP_NATIVE` | `BENIGN_BOUNDARY` | 2.010,87 / 2.020,94 / 2.028,37 | 31,26 | 4,36 | 2,16 |
| `RFC_DROP_NATIVE` | `ATTACK_FIXED_MATCHED` | 2.010,77 / 2.020,88 / 2.026,78 | 31,47 | 4,38 | 2,16 |
| `RFC_DROP_NATIVE` | `ATTACK_SWEEP_FLOOD` | 2.011,44 / 2.020,55 / 2.029,64 | 34,22 | 48,15 | 2,23 |

RFC native drop có latency xấp xỉ deadline 2 s vì các query chờ timeout/no-answer.
CPU cao hơn ở flood workload phản ánh tải fragment, không phải overhead riêng
của B5; E5 không được thiết kế như phép đo overhead giữa các workload khác
nhau.

## Kết luận và phạm vi diễn giải

E5 xác nhận routed enforcement path có thể thực thi đúng: B1 và B5 khi
trigger đều drop forged tail, inject TC, đưa Unbound retry TCP và nhận legitimate
answer. Tuy nhiên, B5 không phải defense thống nhất cho mọi pattern: fixed-IPID
matched attack bypass detector và vẫn gây poisoning, còn flood được mitigated khi
detector trigger. RFC native drop chặn poisoning nhưng trả giá availability rõ
rệt. Vì vậy, kết luận phù hợp là failure end-to-end phụ thuộc cả detector
operating region lẫn enforcement/transport policy; trigger rate không thể dùng
thay cho poisoning prevention.

E5 vẫn chỉ là một Docker testbed với một Unbound version, một topology routed,
bốn workload được đăng ký và 20 run/cell. Kết quả không đại diện cho Internet,
không chứng minh deployment readiness và không thay thế đánh giá trên nhiều
resolver, traffic tự nhiên hoặc adaptive attacker. E5 là campaign runtime
duy nhất được giữ lại; các số liệu không được gộp với E1–E4.

## Tệp kết quả và tái lập

- [Protocol source](e5_protocol.json)
- [Cách dựng lab](E5_LAB.md)
- [Runbook](E5_RUNBOOK.md)
- [Routed lab README](tools/routed_lab/README.md)
- [Registration and image manifest](output/E5-routed-s20260902-r001/registered.json)
- [Preflight validation](output/E5-routed-s20260902-r001/preflight.json)
- [Pilot validation](output/E5-routed-s20260902-r001/validation_pilot.json)
- [Sanity validation](output/E5-routed-s20260902-r001/validation_sanity.json)
- [Confirmatory validation](output/E5-routed-s20260902-r001/validation_confirmatory.json)
- [Aggregate confirmatory results](output/E5-routed-s20260902-r001/aggregate_confirmatory.json)
- [Per-run metrics](output/E5-routed-s20260902-r001/metrics_confirmatory.json)
- [Finished marker](output/E5-routed-s20260902-r001/finished.json)

Để chạy một campaign mới, dùng run ID mới và không ghi đè output đã freeze:

```sh
python run_e5.py --stage all --run-id E5-routed-NEW-ID
```
