# E2 — Kết quả thăm dò: ba điều kiện của B5 có thực sự giúp phân biệt không?

> **Trạng thái hiện tại: thăm dò (provisional), chưa phải kết quả E2 xác nhận.**  
> Dữ liệu bên dưới được lấy từ snapshot `E2_20260806_220159`. Snapshot này đủ nhất quán để mô tả những gì luật đã làm trên các cửa sổ mô phỏng được chấm ngay sau sự kiện FRAG2, nhưng chưa đủ để kết luận về đầu độc DNS thật, ASR, hiệu năng hệ thống hoặc triển khai thực tế.

## 1. E2 muốn trả lời câu hỏi gì?

E1 cho thấy B5 có thể giảm số lần bật bảo vệ không cần thiết khi tải fragment hợp lệ thấp. E2 đặt câu hỏi khó hơn:

> Khi lưu lượng hợp lệ và lưu lượng tấn công có **cùng số fragment**, entropy và tỷ lệ IPID khác nhau có giúp B5 phân biệt hai loại lưu lượng không?

Nói đơn giản: nếu chỉ nhìn số lượng fragment là chưa đủ, hai điều kiện entropy và `unique_ratio` có giúp luật B5 thông minh hơn không?

## 2. E2 đã chạy như thế nào?

Snapshot hiện có dùng mô phỏng có kiểm soát, cửa sổ 2 giây và cùng ngưỡng B5 như E1:

| Điều kiện của B5 | Giá trị |
| --- | ---: |
| Số fragment tối thiểu | 24 |
| Entropy tối thiểu | 4,0 |
| Tỷ lệ IPID khác nhau tối thiểu | 0,70 |

Các mức tải là 24, 60, 120 và 200 fragment/cửa sổ. Có 20 lần chạy cho mỗi trường hợp và 150 cửa sổ cho mỗi lần chạy, tổng cộng 72.000 cửa sổ mô phỏng.

Các mô hình lưu lượng gồm một luồng hợp lệ và năm mô hình tấn công tổng hợp: IPID quét tuần tự, IPID ngẫu nhiên, IPID cố định, lưu lượng theo đợt và IPID lặp.

## 3. Kết quả chính của snapshot

**Bảng 1. Tỷ lệ B5 bật bảo vệ trong mô phỏng.**  
FPR là tỷ lệ cửa sổ hợp lệ bị B5 chặn. TPR là tỷ lệ cửa sổ tấn công tổng hợp bị B5 chặn. Đây là tỷ lệ quyết định của detector, **không phải** tỷ lệ đầu độc DNS thành công/thất bại.

| Mức tải | FPR hợp lệ | TPR quét | TPR ngẫu nhiên | TPR theo đợt | TPR IPID cố định | TPR IPID lặp |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 24 | 61,07% | 58,90% | 58,53% | 49,93% | 0,00% | 0,00% |
| 60 | 100,00% | 100,00% | 100,00% | 98,97% | 0,00% | 0,00% |
| 120 | 100,00% | 100,00% | 100,00% | 100,00% | 0,00% | 0,00% |
| 200 | 100,00% | 100,00% | 100,00% | 100,00% | 0,00% | 0,00% |

### Điều rút ra được

1. **Ở các mô hình IPID đa dạng đã thử, B5 gần như chỉ phản ứng theo số lượng fragment.**

   Trong các điều kiện hợp lệ, quét, ngẫu nhiên và theo đợt, B5 cho đúng cùng quyết định với B2 — luật chỉ kiểm tra có đủ fragment hay không — ở 48.000/48.000 cửa sổ. Vì thế, trong các trường hợp này, hai điều kiện entropy và `unique_ratio` không tạo thêm khác biệt cho luật B5 đang cài đặt.

2. **Ở mức tải 24, B5 chưa phân biệt được lưu lượng hợp lệ và ba mô hình tấn công IPID đa dạng.**

   FPR hợp lệ là 61,07%, còn TPR của quét/ngẫu nhiên/theo đợt lần lượt là 58,90%, 58,53% và 49,93%. Các tỷ lệ này gần nhau, nên detector đang phản ứng chủ yếu với mức tải, chưa thể hiện khả năng tách hai loại lưu lượng.

3. **Từ mức tải 60 trở lên, B5 gần như chặn tất cả các cửa sổ IPID đa dạng.**

   Khi đó FPR hợp lệ là 100%, đồng thời TPR của quét và ngẫu nhiên cũng là 100%. Điều này không có nghĩa detector tốt; nó cho thấy luật bị chi phối bởi ngưỡng số fragment.

4. **Hai mô hình IPID ít đa dạng không bị B5 chặn trong snapshot.**

   Với mô hình IPID cố định và IPID lặp, TPR của B5 là 0% ở cả bốn mức tải. Trong cùng dữ liệu, luật chỉ đếm số fragment vẫn chặn từ 59,37% đến 100% tùy mức tải. Đây là một dấu hiệu đáng lo về cách đặt cổng entropy/`unique_ratio`, nhưng mới là kết quả detector-level trong mô phỏng.

5. **Không nên kết luận bản thân `unique_ratio` hoàn toàn vô ích.**

   Trong một số mô hình quét/theo đợt ở tải cao, `unique_ratio` có giá trị PR-AUC được lưu khá cao (ví dụ 0,907 và 0,993 cho quét ở mức 120 và 200). Tuy nhiên, các PR-AUC này chưa có khoảng tin cậy theo lần chạy và chọn chiều điểm tốt hơn sau khi xem dữ liệu. Chúng chỉ là gợi ý để thiết kế lại luật, không phải bằng chứng xác nhận rằng `unique_ratio` sẽ giúp trong hệ thống thật.

## 4. Đoạn có thể chép vào báo cáo hôm nay

> **Kết quả thăm dò E2.** E2 so sánh lưu lượng hợp lệ và các mô hình lưu lượng tấn công tổng hợp tại cùng mức fragment. Trong snapshot mô phỏng hiện có, B5 cho cùng quyết định với luật chỉ xét số fragment ở 48.000/48.000 cửa sổ thuộc các điều kiện IPID đa dạng đã thử. Ở mức 24 fragment/cửa sổ, FPR của lưu lượng hợp lệ là 61,07%, trong khi TPR của các mô hình quét, ngẫu nhiên và theo đợt lần lượt là 58,90%, 58,53% và 49,93%; từ mức 60 trở lên, B5 chặn gần như toàn bộ các cửa sổ IPID đa dạng. Ngược lại, B5 không chặn các mô hình IPID cố định và IPID lặp trong snapshot này. Kết quả cho thấy luật ba ngưỡng hiện tại bị chi phối mạnh bởi ngưỡng số fragment và có thể bỏ sót một số mẫu IPID ít đa dạng. Tuy nhiên, đây mới là kết quả mô phỏng ở mức detector; chưa thể dùng để khẳng định về ASR, đầu độc DNS thật hoặc hiệu năng hệ thống.

## 5. Không nên viết gì trong bài báo cáo?

Không dùng E2 hiện tại để viết rằng:

- B5 làm hệ thống DNS an toàn hơn hoặc nhanh hơn.
- B5 làm giảm xác suất đầu độc DNS trong hệ thống thật.
- Mô hình IPID cố định/lặp đã chứng minh một cuộc tấn công thành công ngoài mạng thật.
- B5 giữ nguyên độ bao phủ của Rℓ2 gốc.
- `unique_ratio` hoặc entropy hoàn toàn không có thông tin phân biệt.

## 6. Vì sao E2 chưa được coi là kết quả xác nhận?

- Harness chấm điểm sau sự kiện FRAG2, trong khi resolver thật ra quyết định ở thời điểm query/FRAG1 sau đó.
- Các cửa sổ trong cùng một lần chạy chồng lên nhau rất mạnh; PR-AUC hiện có chưa có khoảng tin cậy theo lần chạy và còn chọn chiều điểm tốt hơn sau khi xem dữ liệu.
- Việc khớp mức tải dùng lại seed của báo cáo, chưa có tập kiểm tra độc lập.
- Snapshot không lưu chuỗi IPID, thời điểm sự kiện, kết quả đầu độc hay ASR.
- Chưa có bản chụp mã nguồn/cấu hình/môi trường đầy đủ cho lượt chạy này.

## 7. Việc cần làm để E2 trở thành kết quả chính thức

1. Sửa harness để quyết định ở đúng thời điểm query/FRAG1.
2. Lưu event-level raw gồm IPID, thời điểm, nguồn benign/attack và quyết định.
3. Tách calibration, validation và held-out test; không dùng seed báo cáo để hiệu chỉnh tải.
4. Tính khoảng tin cậy theo lần chạy độc lập, không gộp các cửa sổ chồng lên nhau.
5. Chạy lại thành một phiên bản mới có mã nguồn, cấu hình, câu lệnh và môi trường được khóa.

## 8. Nguồn dữ liệu

- Snapshot provisional: [`E2_20260806_220159`](runs/provisional/E2_20260806_220159/)
- Bảng tổng hợp: [`e2_summary.csv`](runs/provisional/E2_20260806_220159/e2_summary.csv)
- Kết quả máy đọc: [`e2_results.json`](runs/provisional/E2_20260806_220159/e2_results.json)
- Trạng thái artifact: [`ARTIFACT_STATUS.md`](ARTIFACT_STATUS.md)
- Biên bản kiểm tra: [`EXPERIMENT_AUDIT.md`](EXPERIMENT_AUDIT.md)
